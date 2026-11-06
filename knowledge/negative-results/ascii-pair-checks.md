# A case-bit difference admits punctuation

Checking only that two exact one-byte values are separated by 32
accepts `@` and the grave accent (`40`, `60`) and also `[` and `{`
(`5b`, `7b`). The tested gap-only leaf accepts the first witness under
the pinned local tapscript interpreter. The strong leaf rejects both
using the uppercase interval. Neither valid relation nor byte shape
alone binds provenance.

The numeric interval and gap proof still needs both one-byte guards.
Removing both guards accepts `41 00` for uppercase A or `61 00` for
lowercase a in the local Consensus profile. The local Policy profile
rejects these numeric aliases, and the strong leaf rejects them under
both profiles. See the [tests and metrics](../../src/support/ascii_case/README.md).
Evidence is `locally-reproduced`. Execution is `unclassified`.
