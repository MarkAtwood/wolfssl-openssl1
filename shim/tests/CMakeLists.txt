add_executable(rand_shim_test rand_shim_test.c)
target_include_directories(rand_shim_test PRIVATE
    ${CMAKE_SOURCE_DIR}/shim/include
    ${WOLFSSL_INCLUDE_DIR})
target_link_libraries(rand_shim_test wolfshim wolfssl)
add_test(NAME rand_shim_test COMMAND rand_shim_test)

# AES_KEY_new / AES_KEY_free lifecycle tests.
# -Wno-deprecated-declarations: OpenSSL 1.1.1 marks AES_set_encrypt_key,
# AES_ecb_encrypt, etc. as deprecated.  The shim implements these deprecated
# functions; the tests must call them by design.
add_executable(aes_lifecycle_test aes_lifecycle_test.c)
target_include_directories(aes_lifecycle_test PRIVATE
    ${CMAKE_SOURCE_DIR}/shim/include
    ${WOLFSSL_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR})
target_compile_options(aes_lifecycle_test PRIVATE -Wno-deprecated-declarations)
target_link_libraries(aes_lifecycle_test wolfshim wolfssl)
add_test(NAME aes_lifecycle_test COMMAND aes_lifecycle_test)

# SHA*_CTX_new / SHA*_CTX_free lifecycle and digest correctness tests.
# -Wno-deprecated-declarations: same rationale as aes_lifecycle_test.
add_executable(sha_lifecycle_test sha_lifecycle_test.c)
target_include_directories(sha_lifecycle_test PRIVATE
    ${CMAKE_SOURCE_DIR}/shim/include
    ${WOLFSSL_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR})
target_compile_options(sha_lifecycle_test PRIVATE -Wno-deprecated-declarations)
target_link_libraries(sha_lifecycle_test wolfshim wolfssl)
add_test(NAME sha_lifecycle_test COMMAND sha_lifecycle_test)
