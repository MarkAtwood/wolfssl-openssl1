#!/usr/bin/env bash
# audit-gaps.sh — print every tagged maintenance site in the wolfshim source.
#
# Usage:
#   ./shim/audit-gaps.sh              # all tags
#   ./shim/audit-gaps.sh HIGH         # only HIGH-severity sites (start here)
#   ./shim/audit-gaps.sh SECURITY     # only [SECURITY:*] tags
#   ./shim/audit-gaps.sh CORRECTNESS  # only [CORRECTNESS] tags
#   ./shim/audit-gaps.sh UNSUPPORTED  # only [UNSUPPORTED] tags
#   ./shim/audit-gaps.sh ABI          # only [ABI] review sites
#
# Run this before every wolfSSL upgrade.  Any site tagged [SECURITY:*] or
# [ABI] MUST be manually audited before the upgrade ships.  Start with HIGH.
#
# Tags used in the codebase
# --------------------------
#   WOLFSHIM_GAP[SECURITY:HIGH]       — broken security invariant; no mitigation
#                                       in the current build.  These are bugs.
#   WOLFSHIM_GAP[SECURITY:MEDIUM]     — degraded security property; weakened
#                                       guarantee but not outright broken, or
#                                       exploitability depends on usage pattern.
#   WOLFSHIM_GAP[SECURITY:MITIGATED]  — acknowledged gap with documented
#                                       mitigation in place (e.g. WOLFCRYPT_EXCLUDE=1
#                                       excludes the dangerous code path).  Must be
#                                       re-evaluated if the mitigation changes.
#   WOLFSHIM_GAP[CORRECTNESS]         — behavioural gap that may produce wrong
#                                       output; no severity sub-classification.
#   WOLFSHIM_GAP[UNSUPPORTED]         — feature not implemented; returns
#                                       ERR_R_DISABLED or 0/NULL with no side-effects.
#   WOLFSHIM_REVIEW [ABI]             — accesses wolfSSL struct internals; must be
#                                       re-validated against every wolfSSL release.

set -euo pipefail

SHIM_SRC="$(cd "$(dirname "$0")/src" && pwd)"

# Files compiled into the default build (libwolfshim.a).
# bn_shim.c, ec_shim.c, and rsa_shim.c are NOT in this list — they build as
# separate optional static libraries (libwolfshim_bn.a / _ec.a / _rsa.a) and
# are not linked by default.  Gap counts for those files do not apply to a
# default deployment; they are shown separately in the summary below.
DEFAULT_BUILD_FILES=(
    aes/aes_shim.c
    aesni/aesni_shim.c
    aliases/aliases.c
    chacha/chacha_shim.c
    des/des_modes_bridge.c
    des/des_shim.c
    evp/evp_digest_shim.c
    evp/evp_wolf_bridge.c
    hmac/hmac_shim.c
    legacy_stubs/legacy_cipher_stubs.c
    pkey/pkey_meth_shim.c
    rand/rand_shim.c
    rc4/rc4_shim.c
    rng/shim_rng.c
    sha/sha_shim.c
    stubs/misc_stubs.c
    wolfshim_abi_check.c
)

OPTIONAL_OVERRIDE_FILES=(
    bn/bn_shim.c
    ec/ec_shim.c
    rsa/rsa_shim.c
)

filter="${1:-}"

run_grep() {
    local label="$1"
    local pattern="$2"
    echo "=== $label ==="
    grep -rn --include="*.c" --include="*.h" "$pattern" "$SHIM_SRC" \
        | sed 's|'"$SHIM_SRC/"'||' \
        | sort \
        || true
    echo ""
}

if [[ -z "$filter" || "$filter" == "HIGH" ]]; then
    run_grep "WOLFSHIM_GAP[SECURITY:HIGH] — broken invariants, no mitigation" \
        "WOLFSHIM_GAP\[SECURITY:HIGH\]"
fi

if [[ -z "$filter" || "$filter" == "SECURITY" ]]; then
    run_grep "WOLFSHIM_GAP[SECURITY:MEDIUM]" "WOLFSHIM_GAP\[SECURITY:MEDIUM\]"
    run_grep "WOLFSHIM_GAP[SECURITY:MITIGATED]" "WOLFSHIM_GAP\[SECURITY:MITIGATED\]"
fi

if [[ -z "$filter" || "$filter" == "CORRECTNESS" ]]; then
    run_grep "WOLFSHIM_GAP[CORRECTNESS]" "WOLFSHIM_GAP\[CORRECTNESS\]"
fi

if [[ -z "$filter" || "$filter" == "UNSUPPORTED" ]]; then
    run_grep "WOLFSHIM_GAP[UNSUPPORTED]" "WOLFSHIM_GAP\[UNSUPPORTED\]"
fi

if [[ -z "$filter" || "$filter" == "ABI" ]]; then
    run_grep "WOLFSHIM_REVIEW [ABI]" "WOLFSHIM_REVIEW \[ABI\]"
fi

# Summary counts — split by build scope.
#
# DEFAULT BUILD counts apply to the standard libwolfshim.a link.
# OPTIONAL OVERRIDES counts apply only when bn_shim.c / ec_shim.c / rsa_shim.c
# are explicitly linked (libwolfshim_bn.a / _ec.a / _rsa.a).  Those files are
# not wired into the default build and their gap counts do not reflect a default
# deployment.
echo "=== Summary ==="

count_in_files() {
    local pattern="$1"
    shift
    local total=0
    for f in "$@"; do
        local path="$SHIM_SRC/$f"
        [[ -f "$path" ]] || continue
        local n
        n=$(grep -c "$pattern" "$path" 2>/dev/null || true)
        total=$(( total + n ))
    done
    echo "$total"
}

printf "\n  %-42s %s\n" "Tag" "Default build | Optional overrides"
printf "  %-42s %s\n"  "---" "--------------+-------------------"

for tag in \
    "WOLFSHIM_GAP\[SECURITY:HIGH\]" \
    "WOLFSHIM_GAP\[SECURITY:MEDIUM\]" \
    "WOLFSHIM_GAP\[SECURITY:MITIGATED\]" \
    "WOLFSHIM_GAP\[CORRECTNESS\]" \
    "WOLFSHIM_GAP\[UNSUPPORTED\]" \
    "WOLFSHIM_REVIEW \[ABI\]"
do
    default_count=$(count_in_files "$tag" "${DEFAULT_BUILD_FILES[@]}")
    override_count=$(count_in_files "$tag" "${OPTIONAL_OVERRIDE_FILES[@]}")
    label="${tag//\\/}"
    printf "  %-42s %5d         | %d\n" "$label" "$default_count" "$override_count"
done
echo ""
echo "  Optional override files (not in default libwolfshim.a):"
for f in "${OPTIONAL_OVERRIDE_FILES[@]}"; do
    echo "    src/$f"
done
