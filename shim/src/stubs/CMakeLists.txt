# shim/src/stubs/CMakeLists.txt
# Miscellaneous stub implementations for symbols not covered by other shims.

cmake_minimum_required(VERSION 3.14)

set(STUBS_SHIM_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/misc_stubs.c
)

add_library(wolfshim_stubs STATIC ${STUBS_SHIM_SOURCES})

target_include_directories(wolfshim_stubs
    PUBLIC
        ${CMAKE_SOURCE_DIR}/shim/include
        ${CMAKE_SOURCE_DIR}/wolfssl

    PRIVATE
        ${CMAKE_SOURCE_DIR}/openssl/include
)

# Uncomment to enable debug tracing:
# target_compile_definitions(wolfshim_stubs PRIVATE WOLFSHIM_DEBUG)

target_compile_options(wolfshim_stubs PRIVATE
    -Wno-incompatible-pointer-types
)

if(TARGET wolfssl)
    target_link_libraries(wolfshim_stubs PUBLIC wolfssl)
elseif(TARGET wolfcrypt)
    target_link_libraries(wolfshim_stubs PUBLIC wolfcrypt)
else()
    message(WARNING
        "wolfshim_stubs: neither 'wolfssl' nor 'wolfcrypt' CMake target found.")
endif()

install(TARGETS wolfshim_stubs
    ARCHIVE DESTINATION lib
)
