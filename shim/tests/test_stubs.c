/*
 * test_stubs.c — Minimal stubs for OpenSSL symbols required by libwolfshim.a
 * but not provided by libwolfssl.so.
 *
 * These stubs exist only to satisfy the linker for the shim unit test
 * binaries.  They are NOT part of the shim itself.  The production build
 * (build.sh all) links libwolfshim.a against the full OpenSSL libcrypto which
 * provides real implementations of all these symbols.
 *
 * ERR_put_error
 * -------------
 * aes_shim.c calls ERR_put_error on error paths in AES_wrap_key /
 * AES_unwrap_key.  The unit tests do not exercise those paths, so a no-op
 * stub is safe.  The stub logs to stderr when WOLFSHIM_DEBUG is set so that
 * unexpected calls are visible.
 */

#include <stdio.h>

void ERR_put_error(int lib, int func, int reason,
                   const char *file, int line)
{
#ifdef WOLFSHIM_DEBUG
    fprintf(stderr,
            "[test_stubs] ERR_put_error: lib=%d func=%d reason=%d %s:%d\n",
            lib, func, reason, file ? file : "?", line);
#else
    (void)lib; (void)func; (void)reason; (void)file; (void)line;
#endif
}
