# shim/src/aes/CMakeLists.txt
# Build the AES shim as a static library.

cmake_minimum_required(VERSION 3.14)

# ---------------------------------------------------------------------------
# Source files
# ---------------------------------------------------------------------------
set(AES_SHIM_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/aes_shim.c
)

# ---------------------------------------------------------------------------
# Library target
# ---------------------------------------------------------------------------
add_library(wolfshim_aes STATIC ${AES_SHIM_SOURCES})

# ---------------------------------------------------------------------------
# Include paths
# ---------------------------------------------------------------------------
target_include_directories(wolfshim_aes
    PUBLIC
        # Shim public header (aes_shim.h)
        ${CMAKE_SOURCE_DIR}/shim/include

        # wolfSSL / wolfCrypt public headers
        ${CMAKE_SOURCE_DIR}/wolfssl

    PRIVATE
        # OpenSSL 1.1.1 headers (for type definitions used in #includes)
        ${CMAKE_SOURCE_DIR}/openssl/include
)

# ---------------------------------------------------------------------------
# Compile definitions
# ---------------------------------------------------------------------------
# Uncomment to enable debug tracing to stderr:
# target_compile_definitions(wolfshim_aes PRIVATE WOLFSHIM_DEBUG)

# wolfCrypt feature gates (mirror what your wolfSSL build was configured with)
# Adjust these to match your actual wolfSSL ./configure options.
target_compile_definitions(wolfshim_aes PRIVATE
    # WOLFSSL_AES_CFB          # enable for CFB-1 and CFB-8 support
    # WOLFSSL_AES_OFB          # enable for OFB-128 support
    # HAVE_AES_ECB             # enable for ECB support via wc_AesEcbEncrypt
    # WOLFSSL_AES_DIRECT       # enable for IGE support via wc_AesEncryptDirect
    # HAVE_AES_KEYWRAP         # enable for RFC-3394 key wrap/unwrap support
)

# ---------------------------------------------------------------------------
# Link against wolfSSL/wolfCrypt
# ---------------------------------------------------------------------------
# Expects a target named 'wolfssl' or 'wolfcrypt' to exist in the CMake build.
# Adjust the target name to match how wolfSSL is integrated into this project.
if(TARGET wolfssl)
    target_link_libraries(wolfshim_aes PUBLIC wolfssl)
elseif(TARGET wolfcrypt)
    target_link_libraries(wolfshim_aes PUBLIC wolfcrypt)
else()
    message(WARNING
        "wolfshim_aes: neither 'wolfssl' nor 'wolfcrypt' CMake target found. "
        "Link manually or set WOLFSSL_LIB / WOLFCRYPT_LIB cache variables.")
endif()

# ---------------------------------------------------------------------------
# Install rules (optional)
# ---------------------------------------------------------------------------
install(TARGETS wolfshim_aes
    ARCHIVE DESTINATION lib
)
install(FILES ${CMAKE_SOURCE_DIR}/shim/include/aes_shim.h
    DESTINATION include
)
