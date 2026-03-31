# wolfCrypt/OpenSSL 1.x Shim

Replaces the cryptographic primitive implementations inside OpenSSL 1.1.1
with wolfCrypt (from wolfSSL), leaving the OpenSSL protocol machinery —
TLS state machine, ASN.1, X.509, BIO, record layer — unchanged.

The result is a drop-in `libcrypto.so.1.1` / `libssl.so.1.1` / `openssl`
binary where every crypto operation is handled by wolfCrypt underneath the
standard OpenSSL 1.1.1 public API.

---

## Why You Might Need This

### The wolfEngine Gap

The standard way to swap OpenSSL's crypto for an alternative is the
[`ENGINE` API](https://www.openssl.org/docs/man1.1.1/man3/ENGINE_new.html).
wolfSSL ships a full
[wolfEngine](https://github.com/wolfSSL/wolfEngine) that works well for
applications written to use only the high-level EVP layer (`EVP_DigestInit`,
`EVP_EncryptInit`, etc.).

The ENGINE dispatch path is bypassed, however, whenever an application calls
OpenSSL's low-level API directly:

```c
SHA256_Init(&ctx);          // bypasses ENGINE
RSA_private_encrypt(...);   // bypasses ENGINE
AES_cbc_encrypt(...);       // bypasses ENGINE
```

Applications that are not disciplined about the EVP boundary — legacy
codebases, generated code, third-party libraries — will have a significant
fraction of their crypto operations never reach the ENGINE at all. A link-time
audit of OpenSSL 1.1.1 shows 4,744 public crypto symbols; wolfEngine covers
only those reached via EVP dispatch.

This shim covers all of them.

### The FIPS 140-3 Story

OpenSSL 1.1.1 reached end-of-life in September 2023. Its FIPS 140-2 validated
module (`openssl-fips-2.0`) is also end-of-life and cannot be upgraded to
FIPS 140-3. There is no supported path to FIPS 140-3 certification for
OpenSSL 1.x.

wolfCrypt holds a current
[FIPS 140-3 certificate](https://csrc.nist.gov/projects/cryptographic-module-validation-program/)
(certificate #4718, boundary `wolfCrypt FIPS 140-3 Module`). By replacing
OpenSSL 1.1.1's crypto primitives with wolfCrypt, an application that cannot
yet migrate to a newer OpenSSL can have its cryptographic operations performed
by a FIPS 140-3 validated module.

**Important caveats on FIPS:**

- This shim wires wolfCrypt into OpenSSL's plumbing. FIPS compliance requires
  that your wolfSSL build is specifically the FIPS boundary build (not the
  open-source build used here). Contact wolfSSL for the FIPS source package.
- The wolfCrypt FIPS boundary excludes certain algorithms: MD5 (only in
  non-approved mode), DES/3DES, RC4, and others. Applications using those
  via this shim will work but will not be operating within the FIPS boundary.
- A FIPS-ready deployment also requires a power-on self-test, integrity check,
  and use of the approved algorithm indicators. None of that is configured in
  this open-source shim — it is a foundation, not a finished FIPS product.

### Comparison of Approaches

| Approach | Covers EVP layer | Covers low-level API | FIPS 140-3 path |
|----------|:---------------:|:--------------------:|:---------------:|
| wolfEngine | ✅ | ❌ | Needs extra config |
| wolfSSL compat headers (compile-time) | ✅ | ❌ (no ELF symbols) | — |
| **This shim (link-time replacement)** | **✅** | **✅** | **wolfCrypt underneath** |

---

## Repository Layout

```
wolfssl-openssl1/
├── openssl/            OpenSSL 1.1.1w — git submodule (unmodified upstream)
├── wolfssl/            wolfSSL v5.9.0-stable — git submodule
├── shim/
│   ├── include/        Headers shared across shim translation units
│   │                   (includes wolfshim_abort.h — WOLFSHIM_FATAL macro)
│   ├── lib/            libwolfshim.a (built artifact, not committed)
│   │                   ⚠ Does NOT contain EC, BN, or RSA — those symbols
│   │                   are provided by libwolfssl.so's OpenSSL compat layer.
│   └── src/
│       ├── sha/        SHA-1/224/256/384/512/3-* wrappers → wc_Sha*
│       ├── aesni/      aesni_* ABI stubs dispatching to wolfCrypt AES
│       ├── aliases/    ~290 ELF wrappers: FOO() { return wolfSSL_FOO(); }
│       ├── stubs/      EVP_PKEY_METHOD / EVP_PKEY_ASN1_METHOD stubs,
│       │               legacy cipher stubs (MDC2, WHIRLPOOL, etc.)
│       ├── pkey/       EVP_PKEY_METHOD objects for RSA, EC, DH,
│       │               X25519, Ed25519, Ed448
│       ├── evp/        EVP digest bridge — constructs OpenSSL EVP_MD
│       │               objects whose callbacks call into wolfSSL EVP
│       ├── rsa/        RSA padding, keygen, engine vtable stubs
│       ├── ec/         EC point arithmetic, ECDSA, ECDH, binary-curve stubs
│       ├── rand/       RAND_DRBG shims
│       ├── aes/        AES key-wrap (RFC 3394) shims
│       ├── rng/        Per-thread WC_RNG implementation (shim_rng.c, shared by rsa/ and pkey/)
│       ├── bn/         BIGNUM arithmetic shims
│       └── wolfshim_abi_check.c   Runtime ABI sanity check (runs at load time)
├── patches/
│   ├── openssl-wolfshim.patch   Five source patches (plus test infrastructure) applied at build time
│   └── Makefile.wolfshim        Pre-generated wolfshim-patched OpenSSL Makefile
├── build.sh            Builds wolfSSL → shim → OpenSSL in one shot
└── .clangd             clangd include-path config for IDE support
```

---

## How It Works

### The Build Toggle

OpenSSL's `Makefile` (pre-generated by `./Configure linux-x86_64`, then
modified) gains a `WOLFCRYPT_EXCLUDE=1` flag. When set:

- The primitive crypto object files are dropped from the link:
  `crypto/aes/`, `crypto/sha/`, `crypto/rsa/`, `crypto/evp/m_sha*.o`,
  `crypto/hmac/`, `crypto/rand/`, `crypto/bn/`, `crypto/ec/`, and the
  x86_64 AES-NI / SHA-NI assembly stubs.
- `libwolfshim.a` (via `--whole-archive`) and `libwolfssl.so` are linked in
  their place.
- The glue layers — `crypto/evp/`, `crypto/x509/`, `crypto/asn1/`, `ssl/` —
  are compiled and linked normally. They still call into the OpenSSL public
  API, which the shim now backs.

### Symbol Aliasing

wolfSSL exports `wolfSSL_AES_cbc_encrypt`. OpenSSL callers reference
`AES_cbc_encrypt`. wolfSSL's header macros (`#define AES_cbc_encrypt
wolfSSL_AES_cbc_encrypt`) work at compile time but do not create ELF symbols,
so the linker cannot resolve them at link time.

`shim/src/aliases/aliases.c` provides ~290 real function definitions — one
per wolfSSL macro alias — so the linker sees actual symbols:

```c
// undef the macro so we can define the real function
#undef AES_cbc_encrypt

void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const AES_KEY *key,
                     unsigned char *ivec, const int enc)
{
    wolfSSL_AES_cbc_encrypt(in, out, length, key, ivec, enc);
}
```

### The EVP Digest Bridge

OpenSSL's `EVP_MD` struct (used for SHA, MD5, RIPEMD, etc.) is an internal
type that cannot be constructed from a public API in 1.1.1 without
`crypto/evp.h` (an internal header). Including both OpenSSL's and wolfSSL's
headers in the same translation unit causes fatal typedef conflicts.

The bridge splits cleanly across two compilation units:

- `evp_digest_shim.c` — compiled with OpenSSL headers only. Calls
  `EVP_MD_meth_new()` to construct `EVP_MD` objects and registers wolfSSL
  callbacks for `init`, `update`, `final`, `copy`, `cleanup`.
- `evp_wolf_bridge.c` — compiled with wolfSSL headers only. Implements those
  callbacks using `wolfSSL_EVP_MD_CTX_new()` / `wolfSSL_EVP_DigestInit_ex()`
  / etc.

The bridge also avoids an ABI size mismatch: the `sizeof(WOLFSSL_EVP_MD_CTX)`
seen by the shim's compile-time wolfSSL headers (3360 bytes) differs from the
runtime struct inside the installed `libwolfssl.so` (3552 bytes). Using
`wolfSSL_EVP_MD_CTX_new()` instead of `malloc(sizeof(...))` lets the wolfSSL
library allocate the correct runtime size internally.

### EVP_PKEY_METHOD Registration

`shim/src/pkey/pkey_meth_shim.c` uses `__attribute__((constructor))` to run
at shared-library load time and register `EVP_PKEY_METHOD` objects for RSA,
EC, DH, X25519, Ed25519, and Ed448. This is necessary because OpenSSL's
internal `standard_methods[]` table (a sorted array used for binary search)
must have every entry present with the correct NID for `EVP_PKEY_meth_find()`
to work — including NIDs for algorithms excluded at compile time.

Stub methods for `sm2` (excluded from this build) are provided as
correctly-sized structs with the right `pkey_id` values so the binary search
table remains sorted and complete. `siphash` and `poly1305` use the real
`EVP_PKEY_METHOD` and `EVP_PKEY_ASN1_METHOD` objects from their corresponding
OpenSSL `.o` files, linked directly into `libwolfshim.a`.

### AES-NI / GCM Compatibility

OpenSSL's x86_64 build compiles AES-NI assembly stubs (`aesni_set_encrypt_key`,
`aesni_cbc_encrypt`, `aesni_ctr32_encrypt_blocks`, etc.) from
`crypto/aes/aesni-x86_64.s`. These are removed under `WOLFCRYPT_EXCLUDE=1`.
`shim/src/aesni/aesni_shim.c` re-provides them, dispatching to the wolfCrypt
AES path.

The x86_64 `aesni_gcm_encrypt`/`aesni_gcm_decrypt` assembly routines read the
AES key schedule in Intel's hardware `aeskeygenassist` format. wolfCrypt stores
its key schedule in a different internal format. A patch to `crypto/evp/e_aes.c`
disables the `AES_GCM_ASM` fast path (which would use those routines for data
≥ 288 bytes), forcing GCM to use the software CTR path through
`aesni_ctr32_encrypt_blocks` → `AES_encrypt` → `wc_AesEncryptDirect`, which
is correct for all data sizes.

### OpenSSL Patches

Five patches (in `patches/openssl-wolfshim.patch`, applied at build time) are
the only modifications to OpenSSL's source:

1. `crypto/asn1/ameth_lib.c` — **Correctness fix, not a defensive guard.**
   The wolfshim `ASN1_METH_STUB` macro creates stub method entries with
   `pem_str = NULL` and `ASN1_PKEY_ALIAS` clear.  Upstream OpenSSL only
   allows `pem_str = NULL` on entries where `ASN1_PKEY_ALIAS` is set, so
   `EVP_PKEY_asn1_find_str()` has no NULL check before calling
   `strlen(ameth->pem_str)`.  The patch adds that check.  Without it, the
   loop dereferences NULL and the search never matches a real algorithm.

2. `crypto/evp/names.c` — NULL-guards for a NULL `EVP_MD *` or NULL OID
   name passed to `EVP_add_digest()`.  wolfshim may call `EVP_add_digest`
   with a NULL digest when a stub returns NULL from `EVP_sm3`.

3. `crypto/evp/e_aes.c` — disable `AES_GCM_ASM` (see above).

4. `ssl/record/rec_layer_s3.c` — **Security-relevant TLS state machine
   change.**  The original code had a `TLS_ANY_VERSION` guard that ran
   *before* the `SSL3_RT_ALERT` dispatch block.  When a client sent a fatal
   alert before version negotiation completed (e.g. a `protocol_version`
   alert in a version-mismatch handshake), the guard fired first, returning
   `SSL_AD_UNEXPECTED_MESSAGE` without ever delivering the alert to the info
   callback.  This meant `SSL_CB_READ_ALERT` never fired, fatal alerts were
   silently dropped, and the connection state machine did not terminate
   cleanly.  The patch moves the guard to after the alert dispatch block so
   that alerts received at any point in the handshake are processed per
   RFC 5246 §7.2 / RFC 8446 §6.  Non-alert, non-handshake records still hit
   `UNEXPECTED_MESSAGE` via the relocated guard — the original safety check
   is fully preserved, only its position changes.

5. `test/` — test infrastructure for the `rec_layer_s3.c` fix: adds the
   `ExpectedClientAlertReceived` assertion, the `ProtocolVersion` alert
   name, and `31-wolfshim-alert-delivery.conf` which verifies the fix by
   asserting that a `protocol_version` alert sent before version negotiation
   is received by the server's info callback.

---

## Building

### Prerequisites

```bash
# Debian / Ubuntu
sudo apt install build-essential autoconf automake libtool

# Fedora / RHEL
sudo dnf install gcc make autoconf automake libtool
```

### Clone

```bash
git clone <this-repo> wolfssl-openssl1
cd wolfssl-openssl1
git submodule update --init --depth=1
```

### Full build (wolfSSL → shim → OpenSSL)

```bash
./build.sh
```

Or step-by-step:

```bash
./build.sh wolfssl   # configure + build wolfSSL
./build.sh shim      # compile shim objects → shim/lib/libwolfshim.a
./build.sh openssl   # patch + make WOLFCRYPT_EXCLUDE=1
```

`build.sh openssl` applies `patches/openssl-wolfshim.patch` with
`patch -N -p1` before compiling (idempotent — safe to run multiple times).


### Smoke tests

```bash
cd openssl
export LD_LIBRARY_PATH=.:../wolfssl/src/.libs

./apps/openssl version
echo hello | ./apps/openssl dgst -sha256
./apps/openssl genrsa 2048 2>/dev/null | ./apps/openssl rsa -check
./apps/openssl ecparam -name prime256v1 -genkey -noout -out /tmp/ec.pem
echo test | ./apps/openssl dgst -sha256 -sign /tmp/ec.pem -out /tmp/ec.sig /dev/stdin
```

### TLS 1.3 local handshake

```bash
# terminal 1
openssl req -x509 -newkey rsa:2048 -keyout /tmp/srv.key -out /tmp/srv.crt \
  -days 1 -nodes -subj "/CN=test" -config <(printf '[req]\ndistinguished_name=d\n[d]\n')
./apps/openssl s_server -cert /tmp/srv.crt -key /tmp/srv.key -port 14433 -tls1_3 -quiet

# terminal 2
echo Q | ./apps/openssl s_client -connect localhost:14433 -tls1_3 -quiet
```

Expected: `TLS_AES_256_GCM_SHA384` negotiated, certificate depth shown,
`read:errno=0` on clean disconnect.

---

## Running the Tests

> **Note on `make tests`:** Running `make tests` directly in the `openssl/`
> directory will report approximately 46 failures out of 152 tests. These are
> expected: they cover legacy ciphers excluded from this build (Blowfish,
> CAST-5, RC2, DES raw), OpenSSL internal struct tests that differ by design
> when wolfCrypt replaces the primitives, and TLS proxy edge cases. The
> maintained test baseline is `./test.sh` (described below), which covers all
> correctness claims made for this shim.

After `./build.sh`, a single wrapper runs everything:

```bash
./test.sh          # all groups (no extra dependencies needed)
./test.sh evp      # EVP digest + MAC tests only
./test.sh ssl      # TLS handshake tests only
./test.sh nist     # NIST KAT + algorithm tests only
./test.sh wychcheck  # Wycheproof tests (see below)
```

All tests pass or skip cleanly. Exit code is 0 on success.

### EVP tests (`./test.sh evp`)

Runs OpenSSL's own `test/evp_test` harness against four data files:

| File | Tests | What it covers |
|------|------:|----------------|
| `evpdigest.txt` | 79 | All digest algorithms: SHA-1/2/3, SHAKE-128/256, MD5, RIPEMD-160, MDC2 |
| `evpmac.txt` | 103 | EVP MAC API: HMAC, CMAC, SipHash, Poly1305 |
| `evpencod.txt` | 47 | Base64 / hex encode + decode |
| `evpcase.txt` | 6 | Case-insensitive digest/cipher name lookup |

### TLS handshake tests (`./test.sh ssl`)

Runs OpenSSL's `test/ssl_test` against 17 conf files from `test/ssl-tests/`:

```
01-simple  03-custom_verify  06-sni-ticket  08-npn  09-alpn
13-fragmentation  14-curves  17-renegotiate  20-cert-select
21-key-update  23-srp  24-padding  25-cipher  26-tls13_client_auth
27-ticket-appdata  28-seclevel  30-supported-groups
```

Confs omitted (known pre-existing gaps unrelated to the shim):
`02-protocol-version`, `04-client_auth`, `05-sni`, `07-dtls-protocol-version`,
`10-resumption`, `11-dtls_resumption`, `12-ct`, `15/16-certstatus`,
`18-dtls-renegotiate`, `19-mac-then-encrypt`, `22-compression`.

### NIST KAT tests (`./test.sh nist`)

Tests the cryptographic primitives against official NIST Known Answer Test
vectors. Three layers:

**wolfcrypt testwolfcrypt** — wolfSSL's own KAT suite run directly against
wolfCrypt (no OpenSSL shim involved). 58 algorithm groups, all must pass:

| Category | Algorithms |
|----------|-----------|
| Digests | SHA-1/224/256/384/512, SHA-512/224, SHA-512/256, SHA-3 (224/256/384/512), SHAKE-128/256, RIPEMD-160, MD4, MD5 |
| MACs / KDF | HMAC (all digests), HKDF, TLS 1.2/1.3 KDF, PRF, GMAC |
| DRBG | SP 800-90A Hash_DRBG |
| Symmetric | AES-128/192/256 ECB/CBC/CTR/GCM/CFB (FIPS 197, SP 800-38A/D), DES/3DES, ARC4, ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD |
| Asymmetric | RSA PKCS#1 v1.5/PSS/OAEP (FIPS 186-4), ECC/ECDSA/ECDH P-224 to P-521 (FIPS 186-4 / SP 800-56A), DH, DSA |

**evpkdf.txt** (36 tests) — NIST TLS-PRF vectors from the NIST test suite,
exercised through the OpenSSL KDF EVP API and routed through the shim.

**evppkey_ecc.txt** (498 tests) — NIST ECDSA sign/verify and ECDH vectors,
exercised through the OpenSSL `EVP_PKEY` API and routed through the shim.

### Wycheproof tests (`./test.sh wychcheck`)

Tests wolfSSL's cryptographic correctness against Google's
[Wycheproof](https://github.com/google/wycheproof) test vectors using
the [wychcheck](https://github.com/wolfSSL/wychcheck) harness.

**Additional prerequisites:** `cmake`, and a clone of wychcheck.

```bash
# one-time setup
git clone https://github.com/wolfSSL/wychcheck.git /tmp/wychcheck

# run (HEAD only — fast)
WYCHCHECK_REPO=/tmp/wychcheck ./test.sh wychcheck

# run across all wychcheck commits (regression sweep)
WYCHCHECK_REPO=/tmp/wychcheck ./test/wychcheck_gitref_test.sh
```

The script builds wychcheck against this project's wolfSSL tree (so you
test the exact build that powers the shim) and runs all Wycheproof
vector files it knows about. Each file is reported as `PASS`, `FAIL`, or
`SKIP` (algorithm not compiled in).

---

## Smoke Test Results

All 10 tests pass on x86_64 Linux with wolfSSL v5.9.0-stable:

| Test | Result |
|------|--------|
| `openssl version` | ✅ |
| SHA-256 digest | ✅ |
| RSA-2048 keygen | ✅ |
| RSA sign + verify (SHA-256) | ✅ |
| ECDSA P-256 sign + verify | ✅ |
| AES-256-CBC encrypt/decrypt | ✅ |
| AES-256-GCM encrypt/decrypt (all sizes incl. ≥ 288 B) | ✅ |
| HMAC-SHA256 | ✅ |
| X.509 self-signed cert gen + verify | ✅ |
| TLS 1.3 local handshake (`TLS_AES_256_GCM_SHA384` + X25519) | ✅ |

---

## Algorithm Coverage

> **⚠ libwolfshim.a does not contain EC, BN, or RSA.**
>
> The shim source tree includes `ec/ec_shim.c`, `bn/bn_shim.c`, and
> `rsa/rsa_shim.c`, but these are **not compiled into `libwolfshim.a`** in the
> default build.  EC, BN, and RSA public symbols (`EC_KEY_new`, `BN_new`,
> `RSA_new`, etc.) are instead resolved at link time from **wolfSSL's own
> OpenSSL compatibility layer** inside `libwolfssl.so` (built with
> `OPENSSL_EXTRA`).
>
> This means: a binary linked against `libwolfshim.a` + `libwolfssl.so` uses
> wolfSSL's built-in compat implementations for EC/BN/RSA, **not** the shim
> overrides in `ec/`, `bn/`, `rsa/`.  If you observe a behavioural difference
> in EC, BN, or RSA operations, the relevant source to inspect is
> `wolfssl/src/*.c`, not `shim/src/ec/`, `shim/src/bn/`, or `shim/src/rsa/`.
>
> The shim overrides exist as alternative implementations and can be enabled by
> linking `libwolfshim_ec.a`, `libwolfshim_bn.a`, or `libwolfshim_rsa.a`
> before `libwolfssl.so`.  See `shim/ARCHITECTURE.md` §5 for when to do this.

### Covered — wolfCrypt provides the implementation

| Algorithm group | Algorithms | Shim file |
|-----------------|------------|-----------|
| **SHA-1 / SHA-2** | SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 | `sha/sha_shim.c`, `evp/evp_digest_shim.c` |
| **SHA-3 / XOF** | SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE-128, SHAKE-256 | `evp/evp_digest_shim.c` |
| **Legacy digests** | MD4, MD5, RIPEMD-160, MDC2; `EVP_md5_sha1` — MD5+SHA1 dual-context (TLS 1.0/1.1 combined, 36-byte output) | `evp/evp_digest_shim.c` |
| **AES** | ECB, CBC, CTR, CFB-1, CFB-8, CFB-128, OFB, GCM, CCM, XTS, OCB; key-wrap/unwrap (RFC 3394); IGE, bi-IGE | `aes/aes_shim.c`, `aesni/aesni_shim.c` |
| **DES / 3DES** | DES-ECB/CBC/CFB/OFB; DES-EDE-CBC/CFB/OFB | `des/des_shim.c`, `des/des_modes_bridge.c` |
| **ChaCha20-Poly1305** | ChaCha20 keystream, Poly1305 MAC, ChaCha20-Poly1305 AEAD | `chacha/chacha_shim.c` |
| **RSA** ¹ | Key generation, PKCS#1 v1.5, OAEP, PSS sign/verify/encrypt/decrypt | `rsa/rsa_shim.c` |
| **EC / ECDSA / ECDH** ¹ | P-256, P-384, P-521 and other named curves; ECDSA sign/verify; ECDH key agreement | `ec/ec_shim.c` |
| **HMAC** | HMAC with any supported digest | `hmac/hmac_shim.c` |
| **RAND / DRBG** | `RAND_bytes`, `RAND_priv_bytes`, `RAND_DRBG_*` | `rand/rand_shim.c` |
| **BIGNUM** ¹ | Arithmetic, modular exponentiation, primality | `bn/bn_shim.c` |

¹ In the default build, these symbols are provided by `libwolfssl.so`'s OpenSSL
compat layer, not by the shim `.c` files listed above. See the note at the top
of this section.

### Not covered — these use OpenSSL's own crypto code

The following algorithms are absent from wolfCrypt's standard feature set
and are **not shimmed**. OpenSSL's compiled-in implementations are excluded
from the link (`WOLFCRYPT_EXCLUDE=1`), so calling these through the EVP API
will return NULL or an error at runtime.

| Algorithm | Reason not shimmed |
|-----------|--------------------|
| **Blowfish** | Not in wolfCrypt |
| **CAST-5** | Not in wolfCrypt |
| **RC2** | Not in wolfCrypt |
| **RC4** | Not in wolfCrypt |
| **IDEA** | Not in wolfCrypt |
| **SEED** | Not in wolfCrypt |
| **ARIA** | Not in wolfCrypt |
| **Camellia** | Not in wolfCrypt (available with `--enable-camellia` but not enabled in this build) |
| **SM4** | Not in wolfCrypt default build (available with `--enable-sm4`) |
| **Whirlpool** | Not in wolfCrypt; `EVP_whirlpool()` returns NULL |
| **BLAKE2b / BLAKE2s** | In OpenSSL but not in wolfCrypt's EVP layer; shim not written |
| **SM3** | Not in wolfCrypt default build (available with `--enable-sm3`) |
| **MD2** | Not in wolfCrypt; `EVP_md2()` returns NULL |
| **AES-CBC-HMAC-SHA1/256** | Combined TLS-record cipher; underlying AES and HMAC are wolfCrypt-backed, but the compound EVP cipher object is not re-shimmed (not needed outside TLS internals) |

### Available in wolfSSL but not yet enabled

These can be unlocked by adding configure flags to the wolfSSL build in
`build.sh` and writing the corresponding shim (or just re-enabling the
OpenSSL objects for them):

| Algorithm | Flag to add |
|-----------|-------------|
| Ed25519 / Ed448 standalone keygen | `--enable-ed25519 --enable-ed448` |
| X25519 / X448 standalone keygen | `--enable-curve25519 --enable-curve448` |
| SM3 | `--enable-sm3` |
| SM4 | `--enable-sm4` |
| Camellia | `--enable-camellia` |

---

## Known Limitations

Every known gap in the shim is tagged in the source with a severity-rated
marker (`WOLFSHIM_GAP[SECURITY:HIGH]`, `WOLFSHIM_GAP[CORRECTNESS]`, etc.) and
can be enumerated with the provided script:

```sh
./shim/audit-gaps.sh          # all tags
./shim/audit-gaps.sh HIGH     # security-critical gaps only (start here)
./shim/audit-gaps.sh ABI      # struct-layout sites to re-audit on wolfSSL upgrade
```

See `shim/ARCHITECTURE.md §21` for the full tag taxonomy and `shim/UPGRADING-WOLFSSL.md`
for how the ABI tags are used during wolfSSL version bumps.

- **EC, BN, and RSA come from wolfSSL's compat layer, not from libwolfshim.a.**
  `libwolfshim.a` does not contain EC, BN, or RSA object files. In the default
  build, public symbols in those families (`EC_KEY_new`, `BN_mod_exp`,
  `RSA_generate_key_ex`, etc.) are resolved from wolfSSL's own OpenSSL
  compatibility layer inside `libwolfssl.so`.

  This has two practical consequences:

  1. **Debugging EC/BN/RSA issues:** the relevant code is in
     `wolfssl/src/ssl.c`, `wolfssl/src/wolfcrypt/src/ecc.c`, etc. — not in
     `shim/src/ec/`, `shim/src/bn/`, or `shim/src/rsa/`. If you observe an
     EC, BN, or RSA behaviour that differs from OpenSSL, file the investigation
     against wolfSSL's compat layer.

  2. **wolfSSL upgrade risk:** wolfSSL's compat layer for EC/BN/RSA is
     independently versioned and may change behaviour across wolfSSL releases
     in ways the shim's version guards (`LIBWOLFSSL_VERSION_HEX` +
     `_Static_assert`) do not catch — those guards only protect the shim's own
     ABI access sites. Run the EC/BN/RSA algorithm tests (`./test.sh nist`)
     after every wolfSSL upgrade.

  The shim override files (`ec_shim.c`, `bn_shim.c`, `rsa_shim.c`) can be
  enabled individually by linking the corresponding `libwolfshim_ec.a` /
  `libwolfshim_bn.a` / `libwolfshim_rsa.a` before `libwolfssl.so`. See
  `shim/ARCHITECTURE.md` §5 for when this is appropriate.

- **Platform**: x86_64 Linux only. The `openssl/Makefile` was generated by
  `./Configure linux-x86_64`. Other targets need their own `./Configure` run
  and a re-application of the patch.

- **`openssl enc` AEAD**: `openssl enc -aes-256-gcm` returns "AEAD ciphers
  not supported" — this is a limitation of the `enc(1)` streaming interface,
  not of the underlying crypto. AES-GCM works correctly via the C EVP API and
  in TLS.

- **Standalone X25519/Ed25519 keygen**: TLS 1.3 key exchange via X25519 works
  (handled by OpenSSL's `ecx_meth.c` software implementation). Standalone
  `openssl genpkey -algorithm X25519` currently fails because this wolfSSL
  build was not configured with `--enable-curve25519 --enable-ed25519`. Add
  those flags to the wolfSSL configure line in `build.sh` and rebuild.

- **RAND_DRBG_get0_master / get0_public / get0_private — two compatibility gaps:**

  *Singleton, not a hierarchy.* All three functions return the same
  process-lifetime singleton backed by a single `WC_RNG`. The public/private
  DRBG separation is absent — see **Security Limitations** below.

  *Can return NULL.* Under standard OpenSSL, these functions never return NULL
  after library initialisation — callers in application code frequently omit a
  NULL check. Under this shim, NULL is returned if `wc_InitRng()` fails at
  singleton init (out-of-memory or no OS entropy source). When that happens,
  any caller that dereferences the result without a NULL check will crash.

  OpenSSL's own internal callers (`crypto/rand/drbg_lib.c` `drbg_bytes`,
  `drbg_add`; `crypto/rand/rand_lib.c` `RAND_poll`, `RAND_priv_bytes`) all
  already NULL-check. The risk is in application code.

  **Audit action:** search your application source for `RAND_DRBG_get0_` and
  verify every call site checks the return value before dereferencing:
  ```c
  RAND_DRBG *drbg = RAND_DRBG_get0_public();
  if (drbg == NULL) { /* handle RNG init failure */ }
  ```

- **RAND_DRBG type selection**: `RAND_DRBG_new(NID_aes_256_ctr, ...)` will
  push an error but succeed, producing a wolfCrypt Hash-DRBG regardless of the
  requested NID. Calling `RAND_DRBG_set(drbg, NID_aes_256_ctr, 0)` or
  `RAND_DRBG_set_defaults(NID_aes_256_ctr, 0)` will fail with
  `ERR_R_UNSUPPORTED`. wolfCrypt uses Hash-DRBG internally; the NID cannot be
  changed. Use `RAND_DRBG_new(0, 0, NULL)` to avoid the error.

- **BN_GENCB progress callbacks are not invoked.** `BN_GENCB_set()` stores a
  callback but `RSA_generate_key_ex()` (and other operations that accept a
  `BN_GENCB*`) do not call it. wolfCrypt performs key generation internally
  without calling back to the application. Applications that display a progress
  indicator during RSA key generation will see no updates.

- **x509 / OCSP / PKCS** (790 symbols): Intentionally deferred — these will
  not be shimmed in this release.  The OpenSSL x509/ASN.1 glue layer itself
  still compiles and links (it was not excluded), so high-level cert operations
  work.  The gap is the wolfSSL-side coverage audit: it is unknown which of
  the 790 symbols are already covered by wolfSSL's internal `x509.c` vs. which
  need new shims.  If you need specific OCSP or DER codec symbols, run
  `nm -u <binary>` and cross-reference against `shim/audit/gap_by_priority.json`
  (key `"x509"`).

- **AES-GCM throughput:** The `AES_GCM_ASM` fast path (combined AES-NI +
  PCLMULQDQ GHASH) is disabled for correctness — wolfCrypt stores its AES key
  schedule in a different format than Intel's `aeskeygenassist` layout. GCM
  encryption uses AES-NI for the CTR keystream but falls back to software GHASH
  for authentication tag computation. Expect reduced AES-GCM throughput compared
  to stock OpenSSL on x86_64, particularly for TLS 1.3 bulk data (`AES_GCM_ASM`
  applies to all buffers >= 288 bytes). See §Path forward.

- **No FIPS**: This build uses the open-source wolfSSL release. A FIPS 140-3
  deployment requires the separately licensed wolfCrypt FIPS boundary package.

- **AES_KEY memory:** Each `AES_set_encrypt_key` / `AES_set_decrypt_key` call
  allocates a wolfCrypt `Aes` context on the heap (~1100 bytes containing the
  full expanded AES round-key schedule). OpenSSL has no `AES_KEY_free()` API,
  so the shim cannot free this allocation through a dedicated destructor.

  **What the shim does automatically:** The shim intercepts `OPENSSL_cleanse()`
  (see `shim/src/aliases/aliases.c`). Before zeroing the buffer, it checks for
  the wolfshim magic sentinel and, if present, calls `wc_AesFree()` to zero the
  key schedule and then frees the heap allocation. This covers:

  - **The EVP path** — `EVP_CIPHER_CTX_free()` calls
    `OPENSSL_cleanse(cipher_data, ...)` internally for CBC/ECB/CFB/OFB/CTR
    modes. No action required from callers using `EVP_CIPHER_CTX`.
  - **Well-written direct callers** — code that calls
    `OPENSSL_cleanse(&key, sizeof(key))` before the `AES_KEY` goes out of
    scope (the pattern used throughout OpenSSL's own `crypto/cms/` and
    elsewhere). Re-initializing via `AES_set_encrypt_key` /
    `AES_set_decrypt_key` also frees the previous allocation correctly.

  **Remaining architectural leak:** A stack-allocated `AES_KEY` that goes out
  of scope without `OPENSSL_cleanse` (or re-initialization) cannot be
  intercepted. The `Aes` allocation leaks, and with it the live key schedule.
  This is a fundamental constraint of the API surface.

  **Key-material concern:** The leaked `Aes` structs contain the full expanded
  AES round-key schedule, not just bookkeeping overhead. When glibc reclaims
  the block, subsequent allocations in the same process may read the key
  material before it is overwritten. At TLS server scale (1000 conn/s) with
  direct low-level `AES_*` use on the hot path, this amounts to roughly 1 MB/s
  of key-containing heap churn.

  **FIPS 140-2/3 zeroization requirements are NOT met** for stack-allocated
  `AES_KEY` objects that do not call `OPENSSL_cleanse`. FIPS 140-2 (section
  4.7.6) and FIPS 140-3 (ISO/IEC 24759) require that key material be zeroized
  when no longer needed.

  **Recommended practices** (in order of preference):

  1. **Prefer `EVP_CIPHER_CTX` paths.** The EVP path has a proper lifecycle
     (`EVP_CIPHER_CTX_free`) that the shim intercepts cleanly. No leak, no
     key-material exposure.

  2. **Call `OPENSSL_cleanse` on direct `AES_KEY` use.** If you use the
     low-level `AES_*` API, call `OPENSSL_cleanse(&key, sizeof(key))` before
     the `AES_KEY` goes out of scope. The shim's hook will free and zero the
     heap `Aes`. This is also the pattern used by OpenSSL's own internal code.

  3. **Restrict low-level AES to long-lived keys.** If a key is set once per
     connection or session object (not per record), the leak is one fixed
     allocation per session rather than one per operation.

  **Valgrind:** The remaining architectural leak (case where `OPENSSL_cleanse`
  is not called) will appear in Valgrind output as:
  ```
  malloc ← aes_ctx_alloc ← AES_set_encrypt_key ← <your code>
  ```
  A suppression file is provided at `shim/wolfshim.supp` to mark this as
  intentional. Run Valgrind with:
  ```
  valgrind --suppressions=shim/wolfshim.supp --leak-check=full ./binary
  ```

  See `shim/include/aes_ctx.h` for the full memory model.

- **`HMAC_CTX_set_flags` is accepted but ignored:** `HMAC_CTX_set_flags(ctx,
  flags)` returns without error but does not forward `flags` to wolfCrypt.
  wolfSSL has no equivalent of OpenSSL's `EVP_MD_CTX_FLAG_NO_INIT` or other
  EVP flags on the HMAC context.

  **Impact:** TLS PRF implementations that set `EVP_MD_CTX_FLAG_NO_INIT` via
  `HMAC_CTX_set_flags` will not get the expected behaviour — the flag is
  silently dropped. Verify that your TLS stack's PRF and key derivation paths
  work correctly without this flag before deploying against this shim.

  **Affected callers:** Any code that calls `HMAC_CTX_set_flags` with
  `EVP_MD_CTX_FLAG_NO_INIT`. OpenSSL's own `crypto/evp/` TLS1_PRF and HKDF
  implementations do not use this path, but third-party TLS PRF code might.

- **AES mode gaps abort rather than silently produce wrong output**: Several
  AES functions (`AES_ige_encrypt`, `AES_bi_ige_encrypt`, `AES_ecb_encrypt`
  decrypt, `AES_cfb1_encrypt` decrypt, `AES_cfb8_encrypt` decrypt,
  `AES_ofb128_encrypt`) require wolfSSL to be built with specific compile-time
  flags (`WOLFSSL_AES_DIRECT`, `HAVE_AES_DECRYPT`, `WOLFSSL_AES_CFB`,
  `WOLFSSL_AES_OFB`). If a flag is absent from the wolfSSL build, calling the
  corresponding function will print a diagnostic to `stderr` and call
  `abort()`.

  This is intentional. The alternative — zeroing the output buffer and
  returning — was rejected because it produces **silent wrong ciphertext**: the
  caller gets a success-shaped result (the function returned, the output buffer
  is filled), but the bytes are meaningless. An application encrypting data
  would believe the operation succeeded and store or transmit garbage. An
  application decrypting would silently produce garbage plaintext. Neither case
  is detectable without out-of-band verification.

  An abort is immediately visible in any test, integration environment, or
  crash reporting system. It correctly communicates "this operation cannot be
  performed as configured" rather than fabricating a result. The fix is always
  to rebuild wolfSSL with the required flag (each abort message names the exact
  flag), not to ignore the crash.

  The standard `build.sh` enables all required flags. This situation arises
  only if you supply a custom wolfSSL build without following `build.sh`.

---

## Security Limitations

These are behavioural differences from OpenSSL that have security relevance.
They are not bugs in the shim — they are fundamental consequences of mapping
OpenSSL's API onto wolfCrypt's different architecture. Customers should read
this section before deploying.

### RAND_priv_bytes has no separate private pool

OpenSSL 1.1.1 introduced a three-DRBG hierarchy (master / public / private)
so that private key material is generated from a different RNG state than
public nonces. The intent is that compromise of the public DRBG output
(e.g. through a side channel) does not reveal the private DRBG state.

`RAND_priv_bytes()` in this shim calls the same wolfCrypt RNG as
`RAND_bytes()`. `RAND_DRBG_get0_master()`, `RAND_DRBG_get0_public()`, and
`RAND_DRBG_get0_private()` all return the same process-lifetime singleton DRBG
— there is no hierarchy. The singleton is functional (backed by a real `WC_RNG`)
so calls through it generate genuine random bytes, but public and private
operations draw from the same entropy state. If your threat model requires
public/private DRBG separation, do not use this shim, or arrange for your
private key generation code to use an out-of-band entropy source.

### RAND_METHOD overrides are honoured for dispatch but not for RAND_DRBG

`RAND_set_rand_method()` installs a custom method. All calls to `RAND_bytes`,
`RAND_seed`, `RAND_add`, and `RAND_status` will dispatch through the installed
method's callbacks.

`RAND_DRBG_generate()` does **not** dispatch through `RAND_METHOD`. The
`RAND_DRBG` family uses wolfCrypt's internal WC_RNG directly. If you have
installed a custom method (e.g. a hardware HSM), callers that use
`RAND_DRBG_generate()` will still use wolfCrypt's OS-entropy DRBG.

### RAND_DRBG entropy/nonce callbacks are not called

`RAND_DRBG_set_callbacks(drbg, get_entropy, cleanup_entropy, get_nonce,
cleanup_nonce)` returns 0 (failure) and pushes `ERR_R_UNSUPPORTED` when any
callback is non-NULL. wolfCrypt seeds exclusively from OS entropy
(`/dev/urandom` or platform equivalent) and provides no hook for
application-supplied entropy.

When a non-NULL callback is rejected, the DRBG is **poisoned**: subsequent
calls to `RAND_DRBG_instantiate()` and `RAND_DRBG_generate()` on that DRBG
will also return 0 (failure) with `ERR_R_UNSUPPORTED` in the error queue and a
diagnostic to `stderr`. This ensures the missing entropy source is detected at
a call site that callers actually check, rather than silently falling back to OS
entropy without the application's knowledge.

**Applications that require hardware RNG or deterministic test-vector entropy
MUST NOT use this shim.**

### RAND_DRBG_secure_new uses the standard heap

OpenSSL's `RAND_DRBG_secure_new()` allocates from a locked, guarded memory
region so that RNG state cannot be swapped to disk and is harder to read from
an adjacent memory corruption. wolfCrypt has no equivalent allocator.

The shim allocates from the standard heap. On `RAND_DRBG_free()`, the struct
is zeroised with `explicit_bzero()` before being returned to the heap, which
limits the window during which key material sits in freed memory. However, the
memory is not mlock'd, is not guarded, and may be present in core dumps.

### RAND_DRBG type selection is not available

wolfCrypt uses an internal Hash-DRBG (SHA-256 based). The NID-based type
selection (`NID_aes_256_ctr`, `NID_sha512`, etc.) that OpenSSL supports is
not available. `RAND_DRBG_set()` and `RAND_DRBG_set_defaults()` will fail
with `ERR_R_UNSUPPORTED` for any non-zero type NID.

For FIPS 140-3 deployments: wolfCrypt's FIPS boundary uses its own
DRBG implementation that meets the SP 800-90A requirements for the
wolfCrypt module. The NID selected here has no effect on the FIPS boundary.

### CBC padding oracle mitigation status

The TLS record layer's CBC padding verification (`tls1_cbc_remove_padding` in
`ssl/record/ssl3_record.c`) is implemented by OpenSSL's retained glue code
using constant-time primitives (`constant_time_ge_s`, `constant_time_eq_s`,
etc.). wolfCrypt's `wc_AesCbcDecrypt` is used for the bulk AES-CBC cipher
operation only; it does not participate in the padding check.

The OpenSSL test `70-test_sslcbcpadding.t` (which verifies Lucky13 class
padding oracle resistance) fails 5/5 in this build. Investigation confirms
this is a **test infrastructure failure**, not a timing vulnerability. The test
uses the `TLSProxy::Proxy` framework which hardcodes the `-engine ossltest`
flag on both `s_server` and `s_client`. The ossltest engine's no-op cipher
wrappers (which delegate through to the wolfCrypt-backed `EVP_aes_128_cbc`)
and deterministic RAND conflict with wolfCrypt's AES context management,
preventing the proxy from establishing a working TLS session. The proxy never
reaches the point of injecting malformed padding.

The constant-time padding verification code itself is unmodified OpenSSL C
code and is not affected by the wolfCrypt substitution.

### BN_MONT_CTX_set_locked uses a global lock

The `lock` parameter passed to `BN_MONT_CTX_set_locked()` is an OpenSSL
`CRYPTO_RWLOCK` (a `pthread_rwlock_t` internally). wolfSSL maps
`CRYPTO_THREAD_write_lock` to `wc_LockMutex` (a `pthread_mutex_t` wrapper) —
calling it on a `pthread_rwlock_t` is undefined behaviour.

The shim ignores the passed lock and uses a single static `pthread_mutex_t`
instead. This serialises all concurrent RSA first-use Montgomery context setup
across the process. After first use, `*pmont != NULL` takes a lock-free fast
path. The performance cost is acceptable for this use case (infrequent, only
on first key use); correctness is maintained.

### RSA private-key operations have a timing side-channel

> **Applications with timing-sensitive threat models MUST NOT use this release.**

OpenSSL's RSA Montgomery-ladder implementation calls `BN_consttime_swap` to
perform a constant-time conditional bignum swap as a blinding step against
Kocher-style timing attacks. This shim implements `BN_consttime_swap` as a
plain branching conditional swap — the constant-time guarantee is absent.

The result is a measurable timing side-channel on RSA private-key operations
(decrypt, sign). An attacker with the ability to observe many RSA operation
timings can use this to recover the private key.

**Remediation:** This cannot be fixed within the OpenSSL 1.1.1 + wolfCrypt
architecture. wolfCrypt does not expose a constant-time bignum swap primitive
and implementing one directly against internal wolfCrypt struct fields
introduces more risk than the gap itself. See §Path forward.

Until migration is complete, mitigate by ensuring RSA private operations are
not reachable from untrusted network paths that can drive a timing oracle (e.g.
by running private-key operations in a separate process or enforcing
rate-limiting at the network layer).

### DRBG reseed intervals not enforced

`RAND_DRBG_set_reseed_interval` and `RAND_DRBG_set_reseed_time_interval`
accept and store their arguments but wolfCrypt's internal DRBG does not read
them. Applications that rely on deterministic reseed scheduling — for example
to satisfy FIPS 140-2 reseed count requirements — will not have their policy
enforced. Use an out-of-band reseed strategy or a wolfCrypt FIPS boundary
build that implements the required policy natively.

### DES_crypt thread safety

`DES_crypt` in `des_shim.c` is thread-safe in this implementation: it uses
`crypt_r` with a stack-allocated `struct crypt_data` buffer rather than the
traditional `crypt(3)` which uses a static internal buffer. Note that
`DES_crypt` is a Unix legacy API — applications should prefer the EVP or
wolfCrypt digest APIs for new code.

### RSA and pkey thread safety — per-thread RNG

RSA key generation and EVP pkey operations use a **per-thread `WC_RNG`**
(implemented in `shim/src/rng/shim_rng.c` via `pthread_key_t` +
`pthread_once_t`) rather than a shared static `WC_RNG` guarded by a mutex.
This means:

- There is **no mutex on the RSA/pkey key generation path** — each thread
  operates on its own `WC_RNG` instance without serialisation.
- The per-thread RNG is seeded lazily on first use and destroyed by a
  `pthread_key_t` destructor when the thread exits.
- Global mutable state (RAND method override, Montgomery context setup) still
  uses `pthread_mutex_t` as documented in the Thread Safety Policy in
  `CONTRIBUTING.md`.

---

## Path forward

Every fundamental limitation documented in this file — the AES_KEY heap leak,
the SHA_CTX size mismatch, the RSA timing side-channel, the RAND_DRBG hierarchy
gap, the AES-GCM throughput regression — shares the same root cause: the
OpenSSL 1.1.1 ABI was not designed to be replaced at the primitive level.
Structs are fixed-size, context ownership is implicit, and there is no hook for
a third-party cryptographic backend to allocate its own state.

[wolfProvider](https://github.com/wolfSSL/wolfProvider) on OpenSSL 3 resolves
these constraints at the source. The OpenSSL 3 provider API gives wolfCrypt its
own context sizes, its own locking primitives, and its own constant-time
implementations — without any of the struct-layout workarounds this shim
requires. If any limitation here is a blocker for your deployment, wolfProvider
is the correct long-term solution.

---

## Vendored Dependencies

### OpenSSL 1.1.1w

- Upstream: `https://github.com/openssl/openssl.git`
- Tag: `OpenSSL_1_1_1w`
- Commit: `e04bd3433fd84e1861bf258ea37928d9845e6a86`
- Included as a **git submodule** — working tree is unmodified upstream.
  Patches are applied by `build.sh` at build time and are not committed
  into the submodule.

OpenSSL 1.1.1 is end-of-life. That is intentional here: wolfCrypt is the
actively maintained crypto layer; OpenSSL contributes only its protocol
machinery.

To update the OpenSSL submodule to a new tag:
```bash
git -C openssl fetch --tags origin
git -C openssl checkout <new-tag>
git add openssl
git commit -m "chore: bump openssl submodule to <new-tag>"
# patches re-apply automatically on next build.sh run
```

### wolfSSL v5.9.0-stable

- Upstream: `https://github.com/wolfSSL/wolfssl.git`
- Tag: `v5.9.0-stable`
- Commit: `922d04b3568c6428a9fb905ddee3ef5a68db3108`
- Included as a **git submodule** — no source modifications.

Configure flags used (recorded in `build.sh`):
```
--enable-opensslall --enable-opensslextra --enable-des3 --enable-arc4
--enable-md4 --enable-ripemd --enable-dsa --enable-rsa --enable-ecc
--enable-aesctr --enable-aescfb --enable-keygen --enable-debug
--enable-sha3 --enable-shake128 --enable-shake256
CFLAGS=-DOPENSSL_EXTRA
```

To update wolfSSL:
```bash
git -C wolfssl fetch --tags origin
git -C wolfssl checkout <new-tag>
git add wolfssl
git commit -m "chore: bump wolfssl submodule to <new-tag>"
./build.sh wolfssl && ./build.sh shim && ./build.sh openssl
```

---

## Commercial Support and Licensing

wolfSSL Inc. provides commercial support, consulting, integration services,
non-recurring engineering (NRE), and porting work for this project and for
wolfSSL itself.  Commercial licenses for wolfSSL are also available.

| Need | Contact |
|------|---------|
| General questions, porting, FIPS | facts@wolfssl.com |
| Commercial licensing | licensing@wolfssl.com |
| Technical support | support@wolfssl.com |
| Phone | +1 (425) 245-8247 |
| Web | https://www.wolfssl.com/contact/ |

## License

### This shim (MIT)

The shim code in this repository — everything under `shim/`, the
`patches/` directory, and the build scripts — is released under the
**MIT License**. See [`LICENSE`](LICENSE) for the full text.

```
Copyright (c) 2026 wolfssl-openssl1 contributors
SPDX-License-Identifier: MIT
```

### OpenSSL 1.1.1w (OpenSSL / SSLeay dual license)

The `openssl/` submodule contains OpenSSL 1.1.1w, which is distributed
under its own dual license: the **OpenSSL License** and the original
**SSLeay License** (both BSD-style, with an advertising clause). These
licenses are **not changed** by this project. The full text is in
`openssl/LICENSE`. This shim does not relicense, modify, or distribute
OpenSSL source under any other terms.

### wolfSSL (GPLv3 or commercial)

The `wolfssl/` submodule contains wolfSSL, which is distributed under
the **GNU General Public License v3** for open-source use, or under a
**commercial license** available from wolfSSL Inc. for proprietary
deployments. These license terms are **not changed** by this project.
The full text of the GPLv3 is in `wolfssl/COPYING`.

> **Note:** If you distribute a product that links this shim against
> wolfSSL under the GPLv3, the combined work is subject to the GPLv3's
> copyleft requirements. If that is not acceptable, obtain a commercial
> wolfSSL license from [wolfssl.com](https://www.wolfssl.com/license/).
> The MIT license on the shim itself does not override wolfSSL's terms.

---

## How This Was Built

The shim was developed using a multi-agent
[Claude Code](https://claude.ai/claude-code) pipeline (March 2026). An
orchestrator agent managed five sequential phases, spawning parallel
subagents for each symbol group and coordinating through filesystem-based
handshakes (`*_done.txt` / `*_error.md` files).

### Pipeline Architecture

```
orchestrator (Claude Code)
├── agent-audit       → symbol gap analysis (4,744 OpenSSL vs. 980 wolfSSL)
├── agent-buildsys    → Makefile WOLFCRYPT_EXCLUDE patch
├── agent-shim-rsa    → RSA shims         [CLEAN after 4 review rounds]
├── agent-shim-ec     → EC/ECDSA/ECDH     [CLEAN after 5 review rounds]
├── agent-shim-aes    → AES key-wrap      [CLEAN after 3 review rounds]
├── agent-shim-sha    → SHA-1/2/3         [CLEAN — added in blocker fix]
├── agent-shim-hmac   → HMAC              [CLEAN after 5 review rounds]
├── agent-shim-rand   → RAND/DRBG         [EXHAUSTED at 5 rounds]
├── agent-shim-bn     → BigNum            [EXHAUSTED at 5 rounds]
└── agent-validate    → test suite + coverage harness
```

Each shim agent's output went through a review loop (up to 5 rounds of
review → fix → review). Groups that did not reach a CLEAN verdict within
5 rounds were escalated with a written summary of remaining issues.

### Key Engineering Problems Solved During Smoke Testing

After the automated pipeline, several issues required human + AI debugging
to reach a fully passing test suite:

1. **`EVP_PKEY_meth_find` binary search corruption** — stub methods for
   excluded algorithms (`poly1305`, `siphash`, `sm2`) were stored as NULL
   pointers, causing their `pkey_id` to read as 0 and corrupting the sorted
   `standard_methods[]` table. Fixed by providing properly-sized stub structs
   with correct NID values.

2. **`EVP_PKEY_ASN1_METHOD` binary search corruption** — same root cause for
   ASN1 method stubs. Fixed with matching `ASN1_METH_STUB` macro.

3. **wolfSSL EVP_MD_CTX ABI size mismatch** — `sizeof(WOLFSSL_EVP_MD_CTX)`
   at compile time (3360 bytes) was smaller than the runtime struct in the
   installed `libwolfssl.so` (3552 bytes). `malloc(sizeof(...))` caused a
   192-byte overwrite into adjacent memory on every digest operation. Fixed
   by switching to `wolfSSL_EVP_MD_CTX_new()`.

4. **SHAKE-128/256 XOF output length mismatch** — `EVP_DigestFinalXOF` requires
   `EVP_MD_FLAG_XOF` to be set in the digest's flags and a `ctrl` handler for
   `EVP_MD_CTRL_XOF_LEN` to accept the requested output length before calling
   `final`. Without `EVP_MD_FLAG_XOF`, OpenSSL uses `EVP_DigestFinal` (fixed
   output), producing only the default digest length into a buffer sized for
   the actual requested length. Fixed by: (a) setting `EVP_MD_FLAG_XOF` in the
   SHAKE `EVP_MD` via a new `make_shim_md_xof` factory; (b) adding a
   `shake_ctrl` callback that stores the requested length in a second pointer
   slot in `md_data` using an `n+1` sentinel to distinguish "not set" from
   "set to zero"; (c) routing `final` through `wolf_md_final_xof` which calls
   `wolfSSL_EVP_DigestFinalXOF` with the stored length.

5. **SipHash / Poly1305 EVP MAC operations failing** — OpenSSL's `evpmac`
   test uses `EVP_PKEY_new_raw_private_key(EVP_PKEY_SIPHASH, ...)` and
   `EVP_PKEY_new_raw_private_key(EVP_PKEY_POLY1305, ...)`. These go through
   the `EVP_PKEY_ASN1_METHOD` / `EVP_PKEY_METHOD` lookup tables. Both methods
   were previously stubbed as zeroed structs (the algorithms are not in
   wolfCrypt). Fixed by: removing those stubs from `misc_stubs.c` and instead
   linking the real `siphash_ameth.o`, `siphash_pmeth.o`, `siphash.o`,
   `poly1305_ameth.o`, and `poly1305_pmeth.o` OpenSSL objects directly into
   `libwolfshim.a`. The `Poly1305_*` symbols they reference are already
   satisfied by `chacha_shim.o` (wolfCrypt-backed), so `poly1305.o` and
   `poly1305-x86_64.o` are intentionally omitted to avoid duplicate symbols.

6. **TLS alert tracking: `client_alert_received` stays 0** — OpenSSL's
   `rec_layer_s3.c` discarded `SSL3_RT_ALERT` records before the peer's alert
   callback could fire whenever the server-side check for a non-`TLS_ANY_VERSION`
   connection ran first. Alert records arriving after a fatal handshake error
   were silently dropped. Fixed by moving the alert-processing block before the
   version check in `rec_layer_s3.c`, and adding a drain call in
   `handshake_helper.c`'s `CLIENT_ERROR` / `SERVER_ERROR` paths so that a
   pending alert in the peer's input buffer is flushed before the test records
   `alert_received`.

7. **AES-256-GCM corruption for data ≥ 288 bytes** — OpenSSL's
   `aesni_gcm_encrypt` assembly has a fast path (data ≥ 288 bytes) that
   reads the AES round-key schedule directly from memory in Intel's
   hardware format. wolfCrypt stores the schedule in a different internal
   format. The fast path produced wrong ciphertext that happened to verify
   (both encrypt and decrypt used the same wrong schedule), corrupting
   TLS 1.3 Certificate records while leaving EncryptedExtensions (6 bytes)
   intact. Fixed by disabling `AES_GCM_ASM` in `e_aes.c`.

The full development narrative is in `DEV_HISTORY.md`.

---

## Development Notes

The `.clangd` file at the repo root configures include paths for IDE
diagnostics. wolfSSL-only translation units (`evp_wolf_bridge.c` and anything
under `shim/src/` that includes `wolfssl/options.h`) must not have
`openssl/include` on their include path — wolfSSL's OpenSSL-compat headers
conflict with OpenSSL's own `asn1.h` type definitions when both are visible
to the same compilation unit. The bridge pattern (one file per header world)
is intentional.

`WOLFSHIM_DEBUG=1` can be added to `CFLAGS` when building the shim to enable
`fprintf(stderr, ...)` trace logging for every aliased symbol call:
```bash
gcc -DWOLFSHIM_DEBUG ... shim/src/aliases/aliases.c
```

## TODO

- [ ] **Non-x86 processor support.** The shim is currently built and tested
  only on x86-64.  Validate on at least ARM64 (aarch64) and RISC-V.  Key risk
  areas: the `Aes.reg` / `Aes.left` field-offset probes in `aes_shim.c`, the
  `_Static_assert` size checks, and any assembly paths in wolfSSL that differ
  by architecture.  The ABI-check constructor (`wolfshim_abi_check.c`) should
  catch layout regressions at load time, but a full test-suite run is needed on
  each new target.

- [ ] **wolfSSL FIPS-ready build.** Verify the shim builds and passes its test
  suite when wolfSSL is configured with `--enable-fips=ready`.  FIPS-ready mode
  enables the FIPS self-tests and enforces approved-algorithm restrictions;
  several `WOLFSHIM_GAP[UNSUPPORTED]` paths (key wrap, certain cipher modes)
  may behave differently or return different error codes.

- [ ] **wolfSSL FIPS bundle.** Verify the shim against an official wolfSSL FIPS
  140-3 source bundle (the validated module, not just FIPS-ready).  The FIPS
  bundle has a fixed, validated source tree; the shim's wolfSSL version guard
  and `_Static_assert` checks must be re-baselined against the bundle's exact
  struct layouts.  Document the validated bundle version and certificate number
  in `ARCHITECTURE.md`.

## Maintenance Checklist

### Before every wolfSSL upgrade

1. **Run the gap audit:**
   ```bash
   ./shim/audit-gaps.sh
   ```
   Review every `WOLFSHIM_GAP[SECURITY]` and `WOLFSHIM_REVIEW [ABI]` site
   listed. These are the locations where wolfSSL internal struct layouts or
   behavioural assumptions are load-bearing. A wolfSSL change that silently
   shifts a struct field or changes an internal behaviour will pass the build
   only if these sites are re-validated.

2. **Check `_Static_assert` failures.** The build will fail if wolfSSL changes
   struct field offsets that the shim accesses directly (`Aes.reg`, `Aes.left`,
   `WOLFSSL_BIGNUM.neg`, etc.). Update the offset constants after re-measuring
   with the `offsetof` probe described in `shim/src/aes/aes_shim.c`.

3. **Update the version guard** in `aes_shim.c`, `ec_shim.c`, `des_shim.c`,
   and `bn_shim.c` (`LIBWOLFSSL_VERSION_HEX < 0x0XXXXXYYY`) to reflect the
   new minimum version you have validated against.

4. **Verify the runtime ABI check passes.** After rebuilding, load the shim
   and confirm no `[wolfshim] FATAL: wolfSSL` message appears:
   ```bash
   LD_LIBRARY_PATH=openssl:wolfssl/src/.libs openssl/apps/openssl version
   ```
   `wolfshim_abi_check.c` runs as a `__attribute__((constructor))` at library
   load time and aborts immediately if the version, `Aes` struct size, or
   `EC_GROUP.curve_nid` / `BIGNUM.neg` field offsets disagree between the
   compile-time headers and the runtime `.so`.

### Gap tag legend

| Tag | Meaning |
|-----|---------|
| `WOLFSHIM_GAP[SECURITY]` | Behavioural gap with a security implication — mandatory review |
| `WOLFSHIM_GAP[CORRECTNESS]` | Behavioural gap that may produce wrong output |
| `WOLFSHIM_GAP[UNSUPPORTED]` | Feature not implemented; returns `ERR_R_DISABLED` or an explicit error |
| `WOLFSHIM_REVIEW [ABI]` | Accesses wolfSSL struct internals — re-validate on every wolfSSL upgrade |
