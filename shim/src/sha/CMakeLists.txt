# shim/src/sha/CMakeLists.txt
# Build the SHA shim as part of libwolfshim.a

cmake_minimum_required(VERSION 3.14)

set(SHA_SHIM_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/sha_shim.c
)

add_library(wolfshim_sha STATIC ${SHA_SHIM_SOURCES})

target_include_directories(wolfshim_sha
    PUBLIC
        ${CMAKE_SOURCE_DIR}/shim/include
        ${CMAKE_SOURCE_DIR}/wolfssl

    PRIVATE
        ${CMAKE_SOURCE_DIR}/openssl/include
)

# Uncomment to enable debug tracing:
# target_compile_definitions(wolfshim_sha PRIVATE WOLFSHIM_DEBUG)

if(TARGET wolfssl)
    target_link_libraries(wolfshim_sha PUBLIC wolfssl)
elseif(TARGET wolfcrypt)
    target_link_libraries(wolfshim_sha PUBLIC wolfcrypt)
else()
    message(WARNING
        "wolfshim_sha: neither 'wolfssl' nor 'wolfcrypt' CMake target found.")
endif()

install(TARGETS wolfshim_sha
    ARCHIVE DESTINATION lib
)
