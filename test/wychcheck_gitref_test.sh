#!/usr/bin/env bash
# test/wychcheck_gitref_test.sh
#
# Run wychcheck Wycheproof tests at one or more git refs (commits/tags/branches)
# against THIS project's built wolfSSL submodule.
#
# Usage:
#   ./test/wychcheck_gitref_test.sh                       # all commits in wychcheck repo
#   ./test/wychcheck_gitref_test.sh HEAD                  # current HEAD only
#   ./test/wychcheck_gitref_test.sh 70b6f33 b6318b2       # specific refs
#   ./test/wychcheck_gitref_test.sh --tags                # all tags only
#
# Environment overrides:
#   WYCHCHECK_REPO   path to wychcheck git repo  (required — no default)
#                    git clone https://github.com/wolfSSL/wychcheck.git /tmp/wychcheck
#   WOLFSSL_DIR      path to built wolfSSL tree   (default: <project>/wolfssl)
#   BUILD_DIR_BASE   where to put cmake build dirs (default: <project>/shim/wychcheck_builds)
#   KEEP_BUILDS      set to 1 to keep build dirs after run

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

WYCHCHECK_REPO="${WYCHCHECK_REPO:-}"
WOLFSSL_DIR="${WOLFSSL_DIR:-${PROJECT_ROOT}/wolfssl}"
BUILD_DIR_BASE="${BUILD_DIR_BASE:-${PROJECT_ROOT}/shim/wychcheck_builds}"
KEEP_BUILDS="${KEEP_BUILDS:-0}"
STATUS_FILE="${PROJECT_ROOT}/shim/audit/wychcheck_gitref_status.md"
STATIC_ARCHIVE="${PROJECT_ROOT}/shim/lib/libwolfssl_static.a"

log() { echo "[$(date -u +%H:%M:%S)] $*"; }
log_status() { mkdir -p "$(dirname "$STATUS_FILE")"; echo "[$(date -u +%H:%M:%S)] $*" >> "$STATUS_FILE"; }

# ── sanity checks ────────────────────────────────────────────────────────────

if [ -z "$WYCHCHECK_REPO" ]; then
    echo "ERROR: WYCHCHECK_REPO is not set." >&2
    echo "" >&2
    echo "  Clone the wychcheck test harness, then re-run:" >&2
    echo "    git clone https://github.com/wolfSSL/wychcheck.git /tmp/wychcheck" >&2
    echo "    WYCHCHECK_REPO=/tmp/wychcheck $0 $*" >&2
    exit 1
fi

if [ ! -d "$WYCHCHECK_REPO/.git" ]; then
    echo "ERROR: WYCHCHECK_REPO=$WYCHCHECK_REPO is not a git repository." >&2
    echo "  git clone https://github.com/wolfSSL/wychcheck.git $WYCHCHECK_REPO" >&2
    exit 1
fi

if [ ! -f "$WOLFSSL_DIR/src/.libs/libwolfssl.so" ]; then
    echo "ERROR: wolfSSL not built at $WOLFSSL_DIR" >&2
    echo "       Run: ./build.sh wolfssl" >&2
    exit 1
fi

if ! command -v cmake &>/dev/null; then
    echo "ERROR: cmake not found in PATH" >&2
    exit 1
fi

# ── build static archive for wychcheck ───────────────────────────────────────
# wolfssl is built with -fvisibility=hidden, so sp_int symbols are hidden in
# the shared lib.  A static archive of the same .o files exposes them to the
# linker, letting wychcheck link against this project's exact wolfssl build.

build_static_archive() {
    log "Building static wolfssl archive for wychcheck linking..."
    mkdir -p "$(dirname "$STATIC_ARCHIVE")"
    ar rcs "$STATIC_ARCHIVE" \
        $(find "$WOLFSSL_DIR/wolfcrypt/src/.libs" -name "*.o" 2>/dev/null) \
        $(find "$WOLFSSL_DIR/src/.libs" -name "*.o" 2>/dev/null)
    log "  → $STATIC_ARCHIVE ($(du -sh "$STATIC_ARCHIVE" | cut -f1))"
}

# Rebuild if any wolfssl .o is newer than the archive
if [ ! -f "$STATIC_ARCHIVE" ] || \
   find "$WOLFSSL_DIR" -name "*.o" -newer "$STATIC_ARCHIVE" 2>/dev/null | grep -q .; then
    build_static_archive
fi

# ── resolve refs to test ─────────────────────────────────────────────────────

resolve_refs() {
    if [ "$1" = "--tags" ]; then
        # all tags
        git -C "$WYCHCHECK_REPO" tag --sort=-creatordate
    else
        # all commits, oldest first so regressions surface in order
        git -C "$WYCHCHECK_REPO" log --reverse --format="%H" 2>/dev/null
    fi
}

declare -a REFS=()

if [ $# -eq 0 ]; then
    # default: all commits
    while IFS= read -r r; do REFS+=("$r"); done < <(resolve_refs "")
elif [ "$1" = "--tags" ]; then
    while IFS= read -r r; do REFS+=("$r"); done < <(resolve_refs "--tags")
    if [ ${#REFS[@]} -eq 0 ]; then
        echo "No tags found in $WYCHCHECK_REPO" >&2
        exit 1
    fi
else
    REFS=("$@")
fi

log "wychcheck_gitref_test: ${#REFS[@]} ref(s) to test"
log "  wychcheck repo : $WYCHCHECK_REPO"
log "  wolfSSL dir    : $WOLFSSL_DIR"
log "  build base     : $BUILD_DIR_BASE"
log ""

log_status "start: ${#REFS[@]} refs, wolfssl=${WOLFSSL_DIR}"

mkdir -p "$BUILD_DIR_BASE"

# ── per-ref test function ─────────────────────────────────────────────────────

declare -a PASS_REFS=()
declare -a FAIL_REFS=()
declare -a ERROR_REFS=()

run_ref() {
    local ref="$1"
    local short="${ref:0:12}"           # short display name
    local slug
    slug="$(echo "$ref" | tr '/' '_' | tr -cd 'A-Za-z0-9._-')"
    local clone_dir="${BUILD_DIR_BASE}/${slug}_src"
    local build_dir="${BUILD_DIR_BASE}/${slug}_build"
    local log_file="${BUILD_DIR_BASE}/${slug}.log"

    log "=== ref: ${short} ==="
    log_status "step ref=${short}: clone+build"

    # Remove stale clone
    rm -rf "$clone_dir" "$build_dir"

    # Clone wychcheck at this ref; use --local for speed
    if ! git clone --quiet --local "$WYCHCHECK_REPO" "$clone_dir" 2>>"$log_file"; then
        log "  ERROR: git clone failed — see $log_file"
        log_status "error ref=${short}: git clone failed"
        ERROR_REFS+=("$ref")
        return
    fi

    if ! git -C "$clone_dir" checkout --quiet "$ref" 2>>"$log_file"; then
        log "  ERROR: git checkout $ref failed — see $log_file"
        log_status "error ref=${short}: checkout failed"
        ERROR_REFS+=("$ref")
        rm -rf "$clone_dir"
        return
    fi

    # Initialize submodules (wycheproof vectors live in a submodule)
    git -C "$clone_dir" submodule update --init --quiet 2>>"$log_file" || true

    # Determine wycheproof vectors path: new commits bundle wycheproof as a
    # submodule; old commits (pre-b6318b2) require WYCHEPROOF_DIR env var.
    # Use the submodule from the cloned src if present, else fall back to the
    # current wychcheck repo's submodule (same vectors, different commit).
    local wycheproof_submod="${clone_dir}/wycheproof"
    if [ ! -d "${wycheproof_submod}/testvectors_v1" ] && \
       [ ! -d "${wycheproof_submod}/testvectors" ]; then
        wycheproof_submod="${WYCHCHECK_REPO}/wycheproof"
    fi

    # cmake configure — wychcheck reads $ENV{WOLFSSL_DIR} for headers;
    # we override WOLFSSL_LIB to use our static archive so sp_int symbols
    # (hidden in the shared lib due to -fvisibility=hidden) are accessible.
    # Also pass WYCHEPROOF_DIR for older CMakeLists that require it explicitly.
    if ! WOLFSSL_DIR="$WOLFSSL_DIR" WYCHEPROOF_DIR="$wycheproof_submod" \
            cmake -B "$build_dir" -S "$clone_dir" \
            -DWOLFSSL_LIB="$STATIC_ARCHIVE" \
            -DCMAKE_BUILD_TYPE=RelWithDebInfo \
            -Wno-dev \
            >> "$log_file" 2>&1; then
        log "  ERROR: cmake configure failed — see $log_file"
        log_status "error ref=${short}: cmake configure failed"
        ERROR_REFS+=("$ref")
        [ "$KEEP_BUILDS" = "1" ] || rm -rf "$clone_dir" "$build_dir"
        return
    fi

    # cmake build
    if ! cmake --build "$build_dir" --parallel >> "$log_file" 2>&1; then
        log "  ERROR: cmake build failed — see $log_file"
        log_status "error ref=${short}: cmake build failed"
        ERROR_REFS+=("$ref")
        [ "$KEEP_BUILDS" = "1" ] || rm -rf "$clone_dir" "$build_dir"
        return
    fi

    # run wychcheck; WYCHEPROOF_DIR tells it where the submodule vectors are
    local exit_code=0
    local out_file="${BUILD_DIR_BASE}/${slug}.out"

    log_status "step ref=${short}: running tests"
    # Run into a file so set -o pipefail doesn't kill the script on test failures.
    WYCHEPROOF_DIR="$wycheproof_submod" "$build_dir/wychcheck" > "$out_file" 2>&1 \
        || exit_code=$?
    cat "$out_file" >> "$log_file"
    # Show summary lines on stdout
    grep -E '^(PASS|FAIL|SKIP|---|\s*files|vectors)' "$out_file" || true

    if [ "$exit_code" -eq 0 ]; then
        log "  PASS  ref=${short}"
        log_status "pass ref=${short}"
        PASS_REFS+=("$ref")
    else
        log "  FAIL  ref=${short} (exit $exit_code) — see $log_file"
        log_status "fail ref=${short}: exit=${exit_code}"
        FAIL_REFS+=("$ref")
    fi

    [ "$KEEP_BUILDS" = "1" ] || rm -rf "$clone_dir" "$build_dir"
}

# ── main loop ────────────────────────────────────────────────────────────────

for ref in "${REFS[@]}"; do
    run_ref "$ref"
    echo ""
done

# ── summary ──────────────────────────────────────────────────────────────────

echo "╔══════════════════════════════════╗"
echo "║  wychcheck gitref test summary   ║"
echo "╚══════════════════════════════════╝"
printf "  Passed : %d\n" "${#PASS_REFS[@]}"
printf "  Failed : %d\n" "${#FAIL_REFS[@]}"
printf "  Errors : %d\n" "${#ERROR_REFS[@]}"

if [ ${#FAIL_REFS[@]} -gt 0 ]; then
    echo ""
    echo "Failed refs:"
    for r in "${FAIL_REFS[@]}"; do echo "  $r"; done
fi

if [ ${#ERROR_REFS[@]} -gt 0 ]; then
    echo ""
    echo "Error refs (build/setup problems):"
    for r in "${ERROR_REFS[@]}"; do echo "  $r"; done
fi

echo ""
echo "Build logs: $BUILD_DIR_BASE/"
echo "Status log: $STATUS_FILE"
log_status "done: pass=${#PASS_REFS[@]} fail=${#FAIL_REFS[@]} error=${#ERROR_REFS[@]}"

# Exit non-zero if any test failed or errored
[ ${#FAIL_REFS[@]} -eq 0 ] && [ ${#ERROR_REFS[@]} -eq 0 ]
