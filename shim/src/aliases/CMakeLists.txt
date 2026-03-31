# shim/src/aliases/CMakeLists.txt
# Build the symbol alias wrappers as a static library.

cmake_minimum_required(VERSION 3.14)

set(ALIASES_SHIM_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/aliases.c
)

add_library(wolfshim_aliases STATIC ${ALIASES_SHIM_SOURCES})

target_include_directories(wolfshim_aliases
    PUBLIC
        ${CMAKE_SOURCE_DIR}/shim/include
        ${CMAKE_SOURCE_DIR}/wolfssl

    PRIVATE
        ${CMAKE_SOURCE_DIR}/openssl/include
)

# Uncomment to enable debug tracing:
# target_compile_definitions(wolfshim_aliases PRIVATE WOLFSHIM_DEBUG)

target_compile_options(wolfshim_aliases PRIVATE
    -Wno-incompatible-pointer-types
)

if(TARGET wolfssl)
    target_link_libraries(wolfshim_aliases PUBLIC wolfssl)
elseif(TARGET wolfcrypt)
    target_link_libraries(wolfshim_aliases PUBLIC wolfcrypt)
else()
    message(WARNING
        "wolfshim_aliases: neither 'wolfssl' nor 'wolfcrypt' CMake target found.")
endif()

install(TARGETS wolfshim_aliases
    ARCHIVE DESTINATION lib
)
