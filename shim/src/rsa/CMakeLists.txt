# shim/src/rsa/CMakeLists.txt
#
# Build the RSA shim static library.
#
# Required CMake variables (set by parent or toolchain file):
#   WOLFSSL_INCLUDE_DIR  - path to the wolfSSL install/source include root
#                          (must expose wolfssl/openssl/rsa.h and
#                           wolfssl/wolfcrypt/rsa.h)
#   OPENSSL_INCLUDE_DIR  - path to OpenSSL 1.1.1 include root (for reference
#                          headers; do not link against OpenSSL)
#
# Optional:
#   WOLFSHIM_DEBUG       - if ON, enables runtime trace logging to stderr

cmake_minimum_required(VERSION 3.10)

project(wolfshim_rsa C)

# ---- source files -----------------------------------------------------------

add_library(wolfshim_rsa STATIC
    rsa_shim.c
)

# ---- include directories ----------------------------------------------------

target_include_directories(wolfshim_rsa
    PUBLIC
        # Shim public headers (rsa_shim.h)
        "${CMAKE_CURRENT_SOURCE_DIR}/../../include"
    PRIVATE
        # wolfSSL headers (WOLFSSL_RSA, wolfSSL_RSA_* APIs, wolfcrypt/rsa.h)
        "${WOLFSSL_INCLUDE_DIR}"
        # OpenSSL 1.1.1 reference headers (for signature verification only)
        "${OPENSSL_INCLUDE_DIR}"
)

# ---- compile definitions ----------------------------------------------------

if(WOLFSHIM_DEBUG)
    target_compile_definitions(wolfshim_rsa PRIVATE WOLFSHIM_DEBUG=1)
endif()

# wolfSSL OpenSSL compatibility layer requires OPENSSL_EXTRA
target_compile_definitions(wolfshim_rsa PRIVATE OPENSSL_EXTRA)

# ---- compiler options -------------------------------------------------------

target_compile_options(wolfshim_rsa PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

# ---- install ----------------------------------------------------------------

install(TARGETS wolfshim_rsa
    ARCHIVE DESTINATION lib
)

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/../../include/rsa_shim.h"
    DESTINATION include
)
