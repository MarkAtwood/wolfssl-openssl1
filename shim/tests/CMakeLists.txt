add_executable(rand_shim_test rand_shim_test.c)
target_include_directories(rand_shim_test PRIVATE
    ${CMAKE_SOURCE_DIR}/shim/include
    ${WOLFSSL_INCLUDE_DIR})
target_link_libraries(rand_shim_test wolfshim wolfssl)
add_test(NAME rand_shim_test COMMAND rand_shim_test)
