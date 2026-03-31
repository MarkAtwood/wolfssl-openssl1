# Upgrading wolfSSL

This document describes the steps required before shipping any wolfSSL version
bump. It exists because the shim directly accesses wolfSSL internal struct
fields at several tagged sites (`WOLFSHIM_REVIEW [ABI]`). If a wolfSSL upgrade
changes a field offset, the shim will silently read or write the wrong bytes —
producing wrong ciphertext, corrupt keys, or exploitable heap corruption —
unless the offset constants are updated first.

**The `_Static_assert` guards catch this at compile time.** Each ABI site has
a `_Static_assert(offsetof(struct, field) == N, ...)` that produces a build
error when the layout changes. The build will not produce a runnable binary
until every failing assert is resolved. Do not suppress these errors; resolving
them is the upgrade procedure.

The `LIBWOLFSSL_VERSION_HEX` floor guard at each site (`< 0x05009000`) prevents
downgrade below the last validated version. After re-auditing a site for a new
wolfSSL version, raise this floor so the site cannot regress to an un-validated
older version without triggering a build error.

---

## Step-by-step upgrade procedure

### 1. Run the ABI checklist

```sh
./shim/audit-gaps.sh ABI
```

Save the output. This is your checklist of every direct struct-field access in
the shim. The count should match the table at the end of this document. A
larger count means new ABI sites were added since this document was written —
update the table before continuing.

### 2. Attempt a build

Point the build at the new wolfSSL and compile:

```sh
make -C shim WOLFSSL_DIR=/path/to/new/wolfssl
```

Any `_Static_assert` failure is a struct layout change that must be resolved
before proceeding. The failure message names the field and the constant to
update.

### 3. Resolve each _Static_assert failure

For each failing assert, run the offsetof probe for that field (see the table
below for the exact command per site), compare the result to the constant in
the source, and update the constant.

Generic probe template — adapt the includes and field name per site:

```sh
cat > /tmp/probe.c << 'EOF'
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
/* add the per-site include from the table */
#include <stddef.h>
#include <stdio.h>
int main(void) {
    printf("offsetof = %zu\n", offsetof(STRUCT, field));
    printf("sizeof   = %zu\n", sizeof(STRUCT));
    return 0;
}
EOF
gcc -I/path/to/wolfssl /tmp/probe.c -o /tmp/probe && /tmp/probe
```

Update the constant in the source to match the probe output, then rebuild and
confirm the assert now passes.

### 4. Raise the version floor at each resolved site

Each site has a version floor of the form:

```c
#if defined(LIBWOLFSSL_VERSION_HEX) && LIBWOLFSSL_VERSION_HEX < 0x05009000
#  error "... re-audit ... before lowering this threshold"
#endif
```

After re-auditing and updating the offset constant, raise `0x05009000` to the
new wolfSSL version hex (e.g. `0x0500a000` for 5.10.0, `0x06000000` for 6.0.0).
The hex encoding is `0xMMmmpppp` (major, minor, patch in hex).

Do not raise the floor without re-running the probe. Do not raise all floors in
one mechanical pass — raise each floor only after that specific site has been
validated.

### 5. Re-run the runtime ABI check

The `wolfshim_abi_check.c` constructor runs three detection layers at library
load time. After all static asserts pass, link the shim and run any program
against it to trigger the constructor checks:

```sh
LD_PRELOAD=./shim/lib/libwolfshim.so /bin/true
```

If the constructor aborts, it will print a message identifying the failing
check. Resolve it the same way as a `_Static_assert` failure.

### 6. Review SECURITY:HIGH gaps

```sh
./shim/audit-gaps.sh HIGH
```

Check whether the new wolfSSL release provides a fix for any open
`WOLFSHIM_GAP[SECURITY:HIGH]` site. In particular:

- **`BN_consttime_swap` (bn_shim.c):** check whether the new wolfSSL exports
  `wolfSSL_BN_consttime_swap` or equivalent. If so, replace the branching
  implementation and remove the gap tag. This is the highest-priority gap in
  the current codebase.

### 7. Build and run the test suite

```sh
make -C openssl test TESTS='-exclude fuzz'
```

All tests that passed before the upgrade must still pass.

Re-run the Wycheproof suite if available:

```sh
cd shim/wychcheck_builds && ./build.sh HEAD
```

Compare the `.out` file against the baseline in `RELEASE-NOTES.md`. New
failures are regressions; new passes may allow gap tags to be removed.

### 8. Sign-off checklist

Before merging the wolfSSL version bump:

- [ ] All `_Static_assert` guards pass
- [ ] All `LIBWOLFSSL_VERSION_HEX` floors raised to the new version
- [ ] `wolfshim_abi_check.c` constructor exits cleanly
- [ ] `WOLFSHIM_GAP[SECURITY:HIGH]` sites reviewed against the new release
- [ ] `make test` passes
- [ ] `RELEASE-NOTES.md` updated with the new wolfSSL version and any changed
      Wycheproof results

**Also required on any OpenSSL version bump (not wolfSSL):**

- [ ] `EVP_PKEY_METHOD` slot count re-verified against the new
      `openssl/include/crypto/evp.h` (`struct evp_pkey_method_st`). The type
      is opaque to `pkey_meth_shim.c` so no `_Static_assert` is possible;
      this must be checked manually. Current validated value: **31 function
      pointer fields**, OpenSSL 1.1.1w. See the `WOLFSHIM_REVIEW [ABI]`
      comment at the top of `shim/src/pkey/pkey_meth_shim.c` for the full
      field list and size calculation.

---

## What NOT to do

**Do not raise version floors without re-running the probes.** The floor
records the last validated version; bumping it mechanically without re-auditing
defeats the purpose. If the `_Static_assert` passes, the offset is genuinely
unchanged — the floor raise is then safe.

**Do not cast an OpenSSL `BIGNUM*` to `WOLFSSL_BIGNUM*`.** The two structs have
incompatible layouts. See `ARCHITECTURE.md §7` (The two-header problem). The
correct pattern for passing OpenSSL bignums to wolfSSL APIs is the
serialize-and-reconstruct path in `rsa_shim.c`.

**Do not remove the `_Static_assert` guards** to silence a build error. A
failing assert is telling you that the shim will produce wrong output with the
new wolfSSL version. Fix the offset constant instead.

**Do not skip `wolfshim_abi_check.c`.** The compile-time guards catch layout
changes in the headers the shim was compiled against. The runtime constructor
catches the case where the deployed `libwolfssl.so` was built with different
compile flags than the headers — a realistic production failure mode.

---

## ABI sites table

One row per distinct `_Static_assert` / direct-field-access cluster. All
offsets validated against wolfSSL 5.9.0, x86_64 Linux with the flags in
`build.sh`.

| File | What is accessed | Validated value | Probe command |
|------|-----------------|-----------------|---------------|
| `aes_shim.c` | `Aes.reg` | `offsetof == 256` | `offsetof(Aes, reg)` — include `wolfssl/wolfcrypt/aes.h` |
| `aes_shim.c` | `Aes.left` (CFB/OFB/XTS/CTS only) | `offsetof == 864` | `offsetof(Aes, left)` — include `wolfssl/wolfcrypt/aes.h`; field absent if those modes disabled |
| `aliases.c` | `Aes.reg` (separate TU from aes_shim.c) | `offsetof == 256` | same probe as `aes_shim.c` above |
| `des_shim.c` | `DES_key_schedule` raw key at byte 0 | `sizeof == 8` | `sizeof(DES_key_schedule)` — include `wolfssl/openssl/des.h` |
| `bn_shim.c` | `WOLFSSL_BIGNUM.neg` | `offsetof == 0` | `offsetof(WOLFSSL_BIGNUM, neg)` — include `wolfssl/openssl/bn.h` |
| `ec_shim.c` | `WOLFSSL_EC_GROUP.curve_idx` | `offsetof == 0` | `offsetof(WOLFSSL_EC_GROUP, curve_idx)` — include `wolfssl/openssl/ec.h` |
| `ec_shim.c` | `WOLFSSL_EC_GROUP.curve_nid` | `offsetof == 4` | `offsetof(WOLFSSL_EC_GROUP, curve_nid)` |
| `ec_shim.c` | `WOLFSSL_EC_GROUP.curve_oid` | `offsetof == 8` | `offsetof(WOLFSSL_EC_GROUP, curve_oid)` |
| `ec_shim.c` | `sizeof(WOLFSSL_EC_GROUP)` | `== 12` | `sizeof(WOLFSSL_EC_GROUP)` |
| `ec_shim.c` | `WOLFSSL_EC_KEY.priv_key` | `offsetof == 16` | `offsetof(WOLFSSL_EC_KEY, priv_key)` — include `wolfssl/openssl/ec.h` |
| `ec_shim.c` | `sizeof(WOLFSSL_EC_KEY)` | `== 56` | `sizeof(WOLFSSL_EC_KEY)` |
| `pkey_meth_shim.c` | OpenSSL `EVP_PKEY_METHOD` slot count | 31 function pointers | See comment at site — verified by inspection of `openssl/include/crypto/evp.h`; no `_Static_assert` possible (opaque type). Re-audit on **OpenSSL** upgrade, not wolfSSL. **Also in sign-off checklist §8.** |

**Note on `wolfshim_abi_check.c`:** The runtime constructor independently
probes `EC_GROUP.curve_nid` and `BIGNUM.neg` using public accessors to cross-check
the compile-time offsets at load time. It also runs an `Aes` struct size canary
test. This is a safety net, not a substitute for the static checks above.
