#!/usr/bin/env python3
"""
Script to restore OpenSSL's native DES implementation in Makefile.wolfshim.

Changes made:
1. Replace 19 WOLFCRYPT_EXCLUDE comment lines with actual compile rules
2. Add ncbc_enc rule after the other DES rules
3. Add 20 DES .o files to libcrypto.so dependency line (after crypto/dh/dh_rfc7919.o)
4. Add 20 DES .o files to libcrypto.a dependency line (after crypto/dh/dh_rfc7919.o)
"""

import re
import sys

MAKEFILE = '/home/mark/wolfssl-openssl1/patches/Makefile.wolfshim'

# The 19 excluded DES files (in order they appear in the Makefile)
EXCLUDED_NAMES = [
    'cbc_cksm', 'cbc_enc', 'cfb64ede', 'cfb64enc', 'cfb_enc',
    'des_enc', 'ecb3_enc', 'ecb_enc', 'fcrypt', 'fcrypt_b',
    'ofb64ede', 'ofb64enc', 'ofb_enc', 'pcbc_enc', 'qud_cksm',
    'rand_key', 'set_key', 'str2key', 'xcbc_enc',
]

# ncbc_enc was not in the excluded list but needs to be added
EXTRA_NAME = 'ncbc_enc'

# All 20 DES .o files for dependency lists
ALL_DES_OBJ = (
    'crypto/des/cbc_cksm.o crypto/des/cbc_enc.o crypto/des/cfb64ede.o '
    'crypto/des/cfb64enc.o crypto/des/cfb_enc.o crypto/des/des_enc.o '
    'crypto/des/ecb3_enc.o crypto/des/ecb_enc.o crypto/des/fcrypt.o '
    'crypto/des/fcrypt_b.o crypto/des/ncbc_enc.o crypto/des/ofb64ede.o '
    'crypto/des/ofb64enc.o crypto/des/ofb_enc.o crypto/des/pcbc_enc.o '
    'crypto/des/qud_cksm.o crypto/des/rand_key.o crypto/des/set_key.o '
    'crypto/des/str2key.o crypto/des/xcbc_enc.o'
)


def make_rule(name):
    """Return a Makefile compile rule for the given DES source file name."""
    return (
        f'crypto/des/{name}.o: crypto/des/{name}.c\n'
        f'\t$(CC)  -I. -Iinclude $(LIB_CFLAGS) $(LIB_CPPFLAGS) -MMD -MF crypto/des/{name}.d.tmp -MT $@ -c -o $@ crypto/des/{name}.c\n'
        f'\t@touch crypto/des/{name}.d.tmp\n'
        f'\t@if cmp crypto/des/{name}.d.tmp crypto/des/{name}.d > /dev/null 2> /dev/null; then \\\n'
        f'\t\trm -f crypto/des/{name}.d.tmp; \\\n'
        f'\telse \\\n'
        f'\t\tmv crypto/des/{name}.d.tmp crypto/des/{name}.d; \\\n'
        f'\tfi'
    )


def main():
    with open(MAKEFILE, 'r') as f:
        content = f.read()

    original_len = len(content)

    # --- Step 1: Replace 19 WOLFCRYPT_EXCLUDE comment lines with compile rules ---
    # Build a single pattern that matches all 19 consecutive comment lines
    comment_lines = [f'# WOLFCRYPT_EXCLUDE: skipping crypto/des/{name}.o' for name in EXCLUDED_NAMES]

    # Find all 19 comment lines as a block
    # We'll search line by line
    lines = content.split('\n')
    new_lines = []
    i = 0
    replaced_comments = False
    while i < len(lines):
        if not replaced_comments and lines[i] == comment_lines[0]:
            # Check if the next 18 lines match
            block = lines[i:i+19]
            if block == comment_lines:
                # Replace with compile rules for 19 files + ncbc_enc
                for name in EXCLUDED_NAMES:
                    rule = make_rule(name)
                    new_lines.extend(rule.split('\n'))
                # Add ncbc_enc rule after the others
                ncbc_rule = make_rule(EXTRA_NAME)
                new_lines.extend(ncbc_rule.split('\n'))
                i += 19
                replaced_comments = True
                print(f"[OK] Replaced 19 WOLFCRYPT_EXCLUDE comments with compile rules + added ncbc_enc rule")
                continue
        new_lines.append(lines[i])
        i += 1

    if not replaced_comments:
        print("[FAIL] Could not find the 19 WOLFCRYPT_EXCLUDE comment block", file=sys.stderr)
        sys.exit(1)

    content = '\n'.join(new_lines)

    # --- Steps 2 & 3: Add DES .o files to libcrypto.so and libcrypto.a dependency lines ---
    # We need to insert DES .o files after 'crypto/dh/dh_rfc7919.o' in the long dependency lines.
    # There are multiple occurrences of crypto/dh/dh_rfc7919.o (line 758, 5220, 2333 rule, 8859 dir rule).
    # We only want to modify the libcrypto.so line (~758) and libcrypto.a line (~5220).
    # Strategy: find lines starting with 'libcrypto$(SHLIB_EXT_SIMPLE) libcrypto$(SHLIB_EXT):'
    # and 'libcrypto.a:' and insert after crypto/dh/dh_rfc7919.o on those lines.

    INSERTION = ' ' + ALL_DES_OBJ
    TARGET_OBJ = 'crypto/dh/dh_rfc7919.o'

    lines = content.split('\n')
    new_lines = []
    modified_so = False
    modified_a = False

    i = 0
    while i < len(lines):
        line = lines[i]
        # Detect libcrypto.so dependency line
        if (not modified_so and
                line.startswith('libcrypto$(SHLIB_EXT_SIMPLE) libcrypto$(SHLIB_EXT):') and
                TARGET_OBJ in line):
            new_line = line.replace(TARGET_OBJ, TARGET_OBJ + INSERTION, 1)
            new_lines.append(new_line)
            modified_so = True
            print(f"[OK] Added DES .o files to libcrypto.so dependency line")
            i += 1
            continue
        # Detect libcrypto.a dependency line
        if (not modified_a and
                line.startswith('libcrypto.a:') and
                TARGET_OBJ in line):
            new_line = line.replace(TARGET_OBJ, TARGET_OBJ + INSERTION, 1)
            new_lines.append(new_line)
            modified_a = True
            print(f"[OK] Added DES .o files to libcrypto.a dependency line")
            i += 1
            continue
        new_lines.append(line)
        i += 1

    if not modified_so:
        print("[FAIL] Could not find libcrypto.so dependency line with crypto/dh/dh_rfc7919.o", file=sys.stderr)
        sys.exit(1)
    if not modified_a:
        print("[FAIL] Could not find libcrypto.a dependency line with crypto/dh/dh_rfc7919.o", file=sys.stderr)
        sys.exit(1)

    content = '\n'.join(new_lines)

    with open(MAKEFILE, 'w') as f:
        f.write(content)

    print(f"[OK] Makefile written ({len(content)} bytes, was {original_len} bytes)")


if __name__ == '__main__':
    main()
