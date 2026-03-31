# shim/src/rng/CMakeLists.txt
# Build rules for the shared per-thread WC_RNG implementation.

cmake_minimum_required(VERSION 3.10)

# ---------------------------------------------------------------------------
# Source files
# ---------------------------------------------------------------------------
set(RNG_SHIM_SOURCES
    shim_rng.c
)

# ---------------------------------------------------------------------------
# Static library target
# ---------------------------------------------------------------------------
add_library(wolfshim_rng STATIC ${RNG_SHIM_SOURCES})

# ---------------------------------------------------------------------------
# Include directories
# ---------------------------------------------------------------------------
target_include_directories(wolfshim_rng
    PUBLIC
        # wolfShim public headers (shim_rng.h)
        ${CMAKE_SOURCE_DIR}/shim/include
    PRIVATE
        # wolfCrypt / wolfSSL headers
        ${CMAKE_SOURCE_DIR}/wolfssl
        ${CMAKE_SOURCE_DIR}/wolfssl/wolfssl
        ${CMAKE_SOURCE_DIR}/wolfssl/wolfcrypt
)

# ---------------------------------------------------------------------------
# Compile options
# ---------------------------------------------------------------------------
target_compile_options(wolfshim_rng PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter
)

# ---------------------------------------------------------------------------
# Link dependencies
# ---------------------------------------------------------------------------
if(TARGET wolfssl)
    target_link_libraries(wolfshim_rng PUBLIC wolfssl)
endif()

# ---------------------------------------------------------------------------
# Install rules (optional)
# ---------------------------------------------------------------------------
# install(TARGETS wolfshim_rng ARCHIVE DESTINATION lib)
# install(FILES ${CMAKE_SOURCE_DIR}/shim/include/shim_rng.h
#         DESTINATION include/wolfshim)
