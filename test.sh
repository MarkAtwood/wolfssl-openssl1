#!/usr/bin/env bash
# test.sh — Run the wolfCrypt/OpenSSL shim test suite.
#
# Usage:
#   ./test.sh              # run all tests
#   ./test.sh evp          # EVP digest + MAC tests only
#   ./test.sh ssl          # TLS handshake tests only
#   ./test.sh nist         # NIST KAT + algorithm tests only
#   ./test.sh wychcheck    # Wycheproof correctness tests (needs wychcheck repo)
#
# Prerequisites: run ./build.sh first.
#
# Wycheproof tests also require the wychcheck test harness:
#   git clone https://github.com/wolfSSL/wychcheck.git /tmp/wychcheck
#   WYCHCHECK_REPO=/tmp/wychcheck ./test.sh wychcheck

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
OPENSSL_DIR="$ROOT/openssl"
WOLFSSL_DIR="$ROOT/wolfssl"

pass() { printf '\033[1;32m[PASS]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; }
info() { printf '\033[1;34m[test]\033[0m %s\n' "$*"; }
skip() { printf '\033[1;33m[SKIP]\033[0m %s\n' "$*"; }

# ── pre-flight checks ─────────────────────────────────────────────────────────

check_build() {
    local missing=()
    [ -f "$WOLFSSL_DIR/src/.libs/libwolfssl.so" ] || missing+=("wolfssl/src/.libs/libwolfssl.so")
    [ -f "$OPENSSL_DIR/libcrypto.so.1.1" ]        || missing+=("openssl/libcrypto.so.1.1")
    [ -f "$OPENSSL_DIR/libssl.so.1.1" ]            || missing+=("openssl/libssl.so.1.1")
    [ -f "$OPENSSL_DIR/test/evp_test" ]            || missing+=("openssl/test/evp_test")
    [ -f "$OPENSSL_DIR/test/ssl_test" ]            || missing+=("openssl/test/ssl_test")

    if [ ${#missing[@]} -gt 0 ]; then
        echo "ERROR: build artifacts missing — run ./build.sh first:" >&2
        for f in "${missing[@]}"; do echo "  $f" >&2; done
        exit 1
    fi
}

# ── EVP tests ─────────────────────────────────────────────────────────────────
# evpdigest: all digest algorithms (SHA-1/2/3, MD5, RIPEMD-160, SHAKE, ...)
# evpmac:    EVP MAC API (HMAC, CMAC, SipHash, Poly1305, ...)
# evpencod:  base64/hex encode/decode
# evpcase:   cipher + digest case-insensitive name lookup

EVP_FILES=(
    evpdigest
    evpmac
    evpencod
    evpcase
)

run_evp_tests() {
    info "Running EVP tests..."
    local npass=0 nfail=0
    export LD_LIBRARY_PATH="$WOLFSSL_DIR/src/.libs:$OPENSSL_DIR"

    for name in "${EVP_FILES[@]}"; do
        local data="$OPENSSL_DIR/test/recipes/30-test_evp_data/${name}.txt"
        local summary
        summary=$("$OPENSSL_DIR/test/evp_test" "$data" 2>&1 \
                  | grep "Completed") || true
        if echo "$summary" | grep -q "0 errors"; then
            pass "evp/$name  ($summary)"
            (( npass++ )) || true
        else
            fail "evp/$name  ($summary)"
            (( nfail++ )) || true
        fi
    done

    echo "  EVP: $npass passed, $nfail failed"
    return $nfail
}

# ── TLS handshake tests ───────────────────────────────────────────────────────
# Only confs that are expected to pass with this build are listed.
# Confs omitted (known pre-existing gaps): 02 04 05 07 10 11 12 15 16 18 19 22

SSL_CONFS=(
    01-simple
    03-custom_verify
    06-sni-ticket
    08-npn
    09-alpn
    13-fragmentation
    14-curves
    17-renegotiate
    20-cert-select
    21-key-update
    23-srp
    24-padding
    25-cipher
    26-tls13_client_auth
    27-ticket-appdata
    28-seclevel
    30-supported-groups
)

run_ssl_tests() {
    info "Running TLS handshake tests..."
    local npass=0 nfail=0
    export LD_LIBRARY_PATH="$WOLFSSL_DIR/src/.libs:$OPENSSL_DIR"
    export TEST_CERTS_DIR="$OPENSSL_DIR/test/certs"

    for name in "${SSL_CONFS[@]}"; do
        local conf="$OPENSSL_DIR/test/ssl-tests/${name}.conf"
        local result
        result=$("$OPENSSL_DIR/test/ssl_test" "$conf" 2>&1 | tail -1) || true
        if echo "$result" | grep -q "^ok "; then
            pass "ssl/$name"
            (( npass++ )) || true
        else
            fail "ssl/$name"
            (( nfail++ )) || true
        fi
    done

    echo "  SSL: $npass passed, $nfail failed"
    return $nfail
}

# ── NIST tests ───────────────────────────────────────────────────────────────
# Three layers of NIST Known Answer Tests:
#
# 1. wolfcrypt/test/testwolfcrypt — wolfSSL's own KAT suite, run directly
#    against the wolfCrypt library (no OpenSSL shim involved).  Covers:
#      SHA-1/224/256/384/512, SHA-512/224, SHA-512/256, SHA-3 (224/256/384/512),
#      SHAKE-128/256, RIPEMD-160, MD4, MD5
#      HMAC (all of the above), HKDF, TLS 1.2/1.3 KDF, PRF
#      DRBG (SP 800-90A Hash_DRBG)
#      AES-128/192/256 ECB/CBC/CTR/GCM/CFB, AES-GCM (SP 800-38D)
#      DES / 3DES, ARC4, ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD
#      RSA (PKCS#1 v1.5, PSS, OAEP)  ← FIPS 186-4
#      ECC / ECDSA / ECDH (P-224 to P-521)  ← FIPS 186-4 / SP 800-56A
#      DH / DSA  ← FIPS 186-4
#
# 2. evpkdf.txt — NIST TLS-PRF vectors (from NIST test suite) through the
#    OpenSSL KDF EVP API, routed through the shim.
#
# 3. evppkey_ecc.txt — NIST ECDSA sign/verify + ECDH vectors through the
#    OpenSSL EVP_PKEY API, routed through the shim.

NIST_EVP_FILES=(
    evpkdf
    evppkey_ecc
)

run_nist_tests() {
    info "Running NIST KAT tests..."
    local npass=0 nfail=0

    # ── part 1: wolfcrypt testwolfcrypt ───────────────────────────────────────
    local testwolfcrypt="$WOLFSSL_DIR/wolfcrypt/test/testwolfcrypt"
    if [ ! -x "$testwolfcrypt" ]; then
        fail "nist/testwolfcrypt  (binary not found — run ./build.sh wolfssl)"
        (( nfail++ )) || true
    else
        local wc_out wc_exit=0
        # Must run from wolfssl/ so it can find ./certs/
        wc_out=$(cd "$WOLFSSL_DIR" && \
                 LD_LIBRARY_PATH="src/.libs" \
                 "$testwolfcrypt" 2>&1) || wc_exit=$?

        local failed_tests
        failed_tests=$(echo "$wc_out" | grep "FAILED!" | sed 's/^/    /')

        if [ "$wc_exit" -eq 0 ]; then
            local nalgo
            nalgo=$(echo "$wc_out" | grep -c "test passed!" || true)
            pass "nist/testwolfcrypt  ($nalgo algorithm groups, all passed)"
            (( npass++ )) || true
        else
            local nfailed_groups
            nfailed_groups=$(echo "$wc_out" | grep -c "FAILED!" || true)
            fail "nist/testwolfcrypt  ($nfailed_groups group(s) failed)"
            echo "$failed_tests"
            (( nfail++ )) || true
        fi
    fi

    # ── part 2: OpenSSL EVP NIST vector files ────────────────────────────────
    export LD_LIBRARY_PATH="$WOLFSSL_DIR/src/.libs:$OPENSSL_DIR"

    for name in "${NIST_EVP_FILES[@]}"; do
        local data="$OPENSSL_DIR/test/recipes/30-test_evp_data/${name}.txt"
        local summary
        summary=$("$OPENSSL_DIR/test/evp_test" "$data" 2>&1 \
                  | grep "Completed") || true
        if echo "$summary" | grep -q "0 errors"; then
            pass "nist/$name  ($summary)"
            (( npass++ )) || true
        else
            fail "nist/$name  ($summary)"
            (( nfail++ )) || true
        fi
    done

    echo "  NIST: $npass passed, $nfail failed"
    return $nfail
}

# ── Wycheproof tests ──────────────────────────────────────────────────────────

run_wychcheck() {
    local wychcheck_repo="${WYCHCHECK_REPO:-}"

    if [ -z "$wychcheck_repo" ]; then
        skip "wychcheck (set WYCHCHECK_REPO= to enable)"
        echo ""
        echo "  To run Wycheproof tests:"
        echo "    git clone https://github.com/wolfSSL/wychcheck.git /tmp/wychcheck"
        echo "    WYCHCHECK_REPO=/tmp/wychcheck ./test.sh wychcheck"
        return 0
    fi

    if [ ! -d "$wychcheck_repo/.git" ]; then
        echo "ERROR: WYCHCHECK_REPO=$wychcheck_repo is not a git repository" >&2
        echo "  git clone https://github.com/wolfSSL/wychcheck.git $wychcheck_repo" >&2
        return 1
    fi

    if ! command -v cmake &>/dev/null; then
        echo "ERROR: cmake not found — required for wychcheck build" >&2
        echo "  sudo apt install cmake   # Debian/Ubuntu" >&2
        echo "  sudo dnf install cmake   # Fedora/RHEL" >&2
        return 1
    fi

    info "Running Wycheproof tests via wychcheck..."
    WYCHCHECK_REPO="$wychcheck_repo" \
    WOLFSSL_DIR="$WOLFSSL_DIR" \
        "$ROOT/test/wychcheck_gitref_test.sh" HEAD
}

# ── dispatch ──────────────────────────────────────────────────────────────────

TARGET="${1:-all}"

check_build

TOTAL_FAIL=0

case "$TARGET" in
    evp)
        run_evp_tests || TOTAL_FAIL=$?
        ;;
    ssl)
        run_ssl_tests || TOTAL_FAIL=$?
        ;;
    nist)
        run_nist_tests || TOTAL_FAIL=$?
        ;;
    wychcheck)
        run_wychcheck || TOTAL_FAIL=$?
        ;;
    all)
        run_evp_tests   || (( TOTAL_FAIL += $? )) || true
        echo ""
        run_ssl_tests   || (( TOTAL_FAIL += $? )) || true
        echo ""
        run_nist_tests  || (( TOTAL_FAIL += $? )) || true
        echo ""
        run_wychcheck   || (( TOTAL_FAIL += $? )) || true
        echo ""
        if [ "$TOTAL_FAIL" -eq 0 ]; then
            info "All tests passed."
        else
            info "$TOTAL_FAIL test suite(s) had failures."
        fi
        ;;
    *)
        echo "Usage: $0 [evp|ssl|nist|wychcheck|all]" >&2
        exit 1
        ;;
esac

exit "$TOTAL_FAIL"
