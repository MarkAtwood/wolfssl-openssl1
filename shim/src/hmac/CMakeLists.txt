# shim/src/hmac/CMakeLists.txt
#
# Build the HMAC shim static library.
#
# Required CMake variables (set by parent or toolchain file):
#   WOLFSSL_INCLUDE_DIR  - path to the wolfSSL install/source include root
#                          (must expose wolfssl/openssl/hmac.h)
#   OPENSSL_INCLUDE_DIR  - path to OpenSSL 1.1.1 include root (for reference
#                          headers; do not link against OpenSSL)
#
# Optional:
#   WOLFSHIM_DEBUG       - if ON, enables runtime trace logging to stderr

cmake_minimum_required(VERSION 3.10)

project(wolfshim_hmac C)

# ---- source files -----------------------------------------------------------

add_library(wolfshim_hmac STATIC
    hmac_shim.c
)

# ---- include directories ----------------------------------------------------

target_include_directories(wolfshim_hmac
    PUBLIC
        # Shim public headers (hmac_shim.h)
        "${CMAKE_CURRENT_SOURCE_DIR}/../../include"
    PRIVATE
        # wolfSSL headers (WOLFSSL_HMAC_CTX, wolfSSL_HMAC_* APIs)
        "${WOLFSSL_INCLUDE_DIR}"
        # OpenSSL 1.1.1 reference headers (for signature verification only)
        "${OPENSSL_INCLUDE_DIR}"
)

# ---- compile definitions ----------------------------------------------------

if(WOLFSHIM_DEBUG)
    target_compile_definitions(wolfshim_hmac PRIVATE WOLFSHIM_DEBUG=1)
endif()

# wolfSSL OpenSSL compatibility layer requires OPENSSL_EXTRA
target_compile_definitions(wolfshim_hmac PRIVATE OPENSSL_EXTRA)

# ---- compiler options -------------------------------------------------------

target_compile_options(wolfshim_hmac PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

# ---- install ----------------------------------------------------------------

install(TARGETS wolfshim_hmac
    ARCHIVE DESTINATION lib
)

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/../../include/hmac_shim.h"
    DESTINATION include
)
