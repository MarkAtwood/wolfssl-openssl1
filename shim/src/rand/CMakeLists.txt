# shim/src/rand/CMakeLists.txt
# Build rules for the RAND/RAND_DRBG wolfShim implementation.

cmake_minimum_required(VERSION 3.10)

# ---------------------------------------------------------------------------
# Source files
# ---------------------------------------------------------------------------
set(RAND_SHIM_SOURCES
    rand_shim.c
)

# ---------------------------------------------------------------------------
# Static library target
# ---------------------------------------------------------------------------
add_library(wolfshim_rand STATIC ${RAND_SHIM_SOURCES})

# ---------------------------------------------------------------------------
# Include directories
# ---------------------------------------------------------------------------
target_include_directories(wolfshim_rand
    PUBLIC
        # wolfShim public headers (rand_shim.h)
        ${CMAKE_SOURCE_DIR}/shim/include
    PRIVATE
        # wolfCrypt / wolfSSL headers
        ${CMAKE_SOURCE_DIR}/wolfssl
        ${CMAKE_SOURCE_DIR}/wolfssl/wolfssl
        ${CMAKE_SOURCE_DIR}/wolfssl/wolfcrypt
        # OpenSSL 1.1.1 headers (for type declarations; do NOT link openssl)
        ${CMAKE_SOURCE_DIR}/openssl/include
)

# ---------------------------------------------------------------------------
# Compile options
# ---------------------------------------------------------------------------
target_compile_options(wolfshim_rand PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter
)

# Enable debug tracing by passing -DWOLFSHIM_DEBUG to cmake or adding it here.
# target_compile_definitions(wolfshim_rand PRIVATE WOLFSHIM_DEBUG)

# ---------------------------------------------------------------------------
# Link dependencies
# ---------------------------------------------------------------------------
# wolfSSL provides wolfSSL_RAND_bytes and wc_RNG_* functions.
# The consuming project is expected to have a wolfssl target; adjust the
# target name if it differs in the top-level CMakeLists.txt.
if(TARGET wolfssl)
    target_link_libraries(wolfshim_rand PUBLIC wolfssl)
endif()

# ---------------------------------------------------------------------------
# Install rules (optional – uncomment if packaging is needed)
# ---------------------------------------------------------------------------
# install(TARGETS wolfshim_rand ARCHIVE DESTINATION lib)
# install(FILES ${CMAKE_SOURCE_DIR}/shim/include/rand_shim.h
#         DESTINATION include/wolfshim)
