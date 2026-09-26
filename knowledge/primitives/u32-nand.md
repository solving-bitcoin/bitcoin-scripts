# Fused u32 NAND

`arithmetic::u32::nand::u32_nand` computes the bitwise NAND of two byte-oriented
u32 words using the repository's shared 256-item Boolean table.

- **Input:** two four-limb u32 words, most-significant byte first, with the
  shared XOR/AND/OR table below them.
- **Output:** `~(left & right)` modulo `2^32`, while preserving the word selected
  by the first offset.
- **Hints:** none. The representative boundary has eight data limbs and zero
  auxiliary hints; witness serialization is excluded from the fragment row.
- **Evidence:** `locally-reproduced` by focused CI. Correctness tests cover
  boundary/pattern words, seeded random words,
  invalid numeric byte limbs, and preserved main/alt-stack state.
- **Execution class:** `unclassified`. The local helper uses a tapscript
  context; this fragment has not been differentially validated against Bitcoin
  Core.

The construction is a fused composition, not a new Boolean table: each byte
uses the existing AND lookup and then applies `255 - result` before moving the
result to the altstack. This makes the additional work four small complements
and avoids a separate bytewise NOT pass.

The representative 0x01234567/0x89abcdef boundary is currently recorded as
190 locking-script bytes with a 272-item combined peak. The script metric and
static non-push count are checked by
`u32_nand_metrics_are_current`; the static count is not an executed-opcode
measurement.

This is a fragment rather than a complete locking script. Numeric range checks
are required before table indexing, and callers must add terminal predicates,
clean-stack handling, canonical ScriptNum checks, and transaction-level
validation as required by their protocol.

See the [u32 implementation README](../../src/arithmetic/u32/README.md), the
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u32-nand`.
