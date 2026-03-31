# shim/src/ec/CMakeLists.txt
#
# Build the EC/ECDSA/ECDH shim static library.
#
# Required CMake variables (set by parent or toolchain file):
#   WOLFSSL_INCLUDE_DIR  - path to the wolfSSL install/source include root
#                          (must expose wolfssl/openssl/ec.h and
#                           wolfssl/wolfcrypt/ecc.h)
#   OPENSSL_INCLUDE_DIR  - path to OpenSSL 1.1.1 include root (for reference
#                          headers; do NOT link against OpenSSL)
#
# Optional:
#   WOLFSHIM_DEBUG       - if ON, enables runtime trace logging to stderr

cmake_minimum_required(VERSION 3.10)

project(wolfshim_ec C)

# ---- source files -----------------------------------------------------------

add_library(wolfshim_ec STATIC
    ec_shim.c
)

# ---- include directories ----------------------------------------------------

target_include_directories(wolfshim_ec
    PUBLIC
        # Shim public headers (ec_shim.h)
        "${CMAKE_CURRENT_SOURCE_DIR}/../../include"
    PRIVATE
        # wolfSSL headers (WOLFSSL_EC_KEY, wolfSSL_EC_* compat APIs,
        # wolfssl/wolfcrypt/ecc.h for wc_X963_KDF)
        "${WOLFSSL_INCLUDE_DIR}"
        # OpenSSL 1.1.1 reference headers (for signature verification only;
        # do not link against OpenSSL)
        "${OPENSSL_INCLUDE_DIR}"
)

# ---- compile definitions ----------------------------------------------------

if(WOLFSHIM_DEBUG)
    target_compile_definitions(wolfshim_ec PRIVATE WOLFSHIM_DEBUG=1)
endif()

# wolfSSL OpenSSL compatibility layer requires OPENSSL_EXTRA
target_compile_definitions(wolfshim_ec PRIVATE
    OPENSSL_EXTRA
    HAVE_ECC
)

# ---- compiler options -------------------------------------------------------

target_compile_options(wolfshim_ec PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    # Suppress pedantic warnings for wolfSSL internal macros that use
    # GNU statement-expression extensions
    -Wno-gnu-statement-expression
)

# ---- install ----------------------------------------------------------------

install(TARGETS wolfshim_ec
    ARCHIVE DESTINATION lib
)

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/../../include/ec_shim.h"
    DESTINATION include
)
