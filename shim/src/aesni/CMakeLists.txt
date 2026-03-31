# shim/src/aesni/CMakeLists.txt
# Build the aesni stub shim as a static library.

cmake_minimum_required(VERSION 3.14)

set(AESNI_SHIM_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/aesni_shim.c
)

add_library(wolfshim_aesni STATIC ${AESNI_SHIM_SOURCES})

target_include_directories(wolfshim_aesni
    PUBLIC
        ${CMAKE_SOURCE_DIR}/shim/include
        ${CMAKE_SOURCE_DIR}/wolfssl

    PRIVATE
        ${CMAKE_SOURCE_DIR}/openssl/include
)

# Uncomment to enable debug tracing:
# target_compile_definitions(wolfshim_aesni PRIVATE WOLFSHIM_DEBUG)

target_compile_options(wolfshim_aesni PRIVATE
    -Wno-incompatible-pointer-types
)

if(TARGET wolfssl)
    target_link_libraries(wolfshim_aesni PUBLIC wolfssl)
elseif(TARGET wolfcrypt)
    target_link_libraries(wolfshim_aesni PUBLIC wolfcrypt)
else()
    message(WARNING
        "wolfshim_aesni: neither 'wolfssl' nor 'wolfcrypt' CMake target found.")
endif()

install(TARGETS wolfshim_aesni
    ARCHIVE DESTINATION lib
)
