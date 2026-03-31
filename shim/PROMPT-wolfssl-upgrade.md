# Prompt: Generate wolfSSL Upgrade Procedure

## When to use

`shim/UPGRADING-WOLFSSL.md` already exists.  **Do not re-run this prompt for
normal upgrades** — follow the procedure in that document directly.

Re-run this prompt only if the set of `WOLFSHIM_REVIEW [ABI]` sites changes
substantially (e.g. after a large refactor of bn_shim, ec_shim, or rsa_shim)
and the existing `UPGRADING-WOLFSSL.md` is too stale to patch incrementally.
When you do re-run it, the generated file will overwrite the existing one —
review the diff carefully to ensure the table and step-by-step procedure are
still accurate.

## How to use

Paste the prompt below into a Claude Code session opened in the
`wolfssl-openssl1/` project root.  Claude Code needs read access to
`shim/src/` and `shim/ARCHITECTURE.md`.  No build system or wolfSSL headers
are required — the prompt works entirely from source comments.

The output file will be written to `shim/UPGRADING-WOLFSSL.md`.
Review the generated table carefully: any row whose "Probe command" column
says "see comment at <file>:<line>" identifies a site whose comment is too
sparse — add an explicit probe command to that source comment before the next
upgrade.

---

## Prompt

```
Read shim/ARCHITECTURE.md (especially §22), then run:

  grep -rn "WOLFSHIM_REVIEW \[ABI\]" shim/src/ --include="*.c" --include="*.h"

For each tagged site, read the surrounding comment block (the 10-20 lines around
each tag) to extract:
  - which struct field is being accessed
  - the current validated offset value
  - what the offset probe command is (usually an offsetof call or compile test)
  - which wolfSSL version it was validated against

Then read shim/audit-gaps.sh to understand the existing tooling.

Write a new file shim/UPGRADING-WOLFSSL.md with the following structure:

1. Overview paragraph: what must happen before shipping any wolfSSL version bump,
   and why (the _Static_assert + version ceiling pattern, and what breaks if you
   skip it).

2. Step-by-step procedure:
   a. Run `shim/audit-gaps.sh ABI` and save the output — this is your checklist.
   b. For each site in the output, what to do: re-run the offset probe, compare
      to the constant in the source, update if changed, raise the version ceiling.
   c. Run `shim/audit-gaps.sh HIGH` and review any SECURITY:HIGH gaps to see if
      the wolfSSL upgrade provides a fix (e.g. wolfSSL_BN_consttime_swap).
   d. Build and run the test suite. Note which tests exist and where they are.
   e. Sign-off checklist (all _Static_asserts pass, all HIGH gaps reviewed,
      version ceilings updated).

3. A table with one row per WOLFSHIM_REVIEW [ABI] site, columns:
   File | Function/context | Field accessed | Current validated offset | Probe command

   Populate the table from what you found in step 1. If a site's comment doesn't
   contain an explicit probe command, write "see comment at <file>:<line>" in
   that column.

4. A short section "What NOT to do": don't bump the version ceiling without
   re-running the probes. Don't cast OpenSSL BIGNUM* to WOLFSSL_BIGNUM* (point
   to ARCHITECTURE.md §7). Don't remove the _Static_assert guards.

Write clearly for an audience that knows C and wolfSSL but has not read the
existing shim source. Do not summarize what you're about to write — just write
the document.
```
