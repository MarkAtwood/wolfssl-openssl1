# shim/src/bn/CMakeLists.txt
#
# Build the BN (Big Number) shim static library.
#
# Required CMake variables (set by parent or toolchain file):
#   WOLFSSL_INCLUDE_DIR  - path to the wolfSSL install/source include root
#                          (must expose wolfssl/openssl/bn.h and wolfssl/ssl.h)
#   OPENSSL_INCLUDE_DIR  - path to OpenSSL 1.1.1 include root (for reference
#                          headers; do not link against OpenSSL)
#
# Optional:
#   WOLFSHIM_DEBUG       - if ON, enables runtime trace logging to stderr

cmake_minimum_required(VERSION 3.10)

project(wolfshim_bn C)

# ---- source files -----------------------------------------------------------

add_library(wolfshim_bn STATIC
    bn_shim.c
)

# ---- include directories ----------------------------------------------------

target_include_directories(wolfshim_bn
    PUBLIC
        # Shim public headers (bn_shim.h)
        "${CMAKE_CURRENT_SOURCE_DIR}/../../include"
    PRIVATE
        # wolfSSL headers (WOLFSSL_BIGNUM, wolfSSL_BN_* APIs, wolfSSL_DH_*_prime)
        "${WOLFSSL_INCLUDE_DIR}"
        # OpenSSL 1.1.1 reference headers (for signature verification only)
        "${OPENSSL_INCLUDE_DIR}"
)

# ---- compile definitions ----------------------------------------------------

if(WOLFSHIM_DEBUG)
    target_compile_definitions(wolfshim_bn PRIVATE WOLFSHIM_DEBUG=1)
endif()

# wolfSSL OpenSSL compatibility layer requires OPENSSL_EXTRA
target_compile_definitions(wolfshim_bn PRIVATE
    OPENSSL_EXTRA
    WOLFSSL_SP_MATH_ALL
)

# ---- compiler options -------------------------------------------------------

target_compile_options(wolfshim_bn PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

# ---- install ----------------------------------------------------------------

install(TARGETS wolfshim_bn
    ARCHIVE DESTINATION lib
)

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/../../include/bn_shim.h"
    DESTINATION include
)
