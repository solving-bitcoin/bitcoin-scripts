# Fused u32 NOR

`arithmetic::u32::nor::u32_nor` computes the bitwise NOR of two byte-oriented
u32 words using the shared 256-item Boolean table.

- **Input:** two four-limb u32 words, most-significant byte first, with the
  shared XOR/AND/OR table below them.
- **Output:** `~(left | right)` modulo `2^32`, while preserving the word selected
  by the first offset.
- **Hints:** none; the fragment consumes eight data limbs and no auxiliary
  hints.
- **Evidence:** `locally-reproduced` by focused CI. Tests cover boundaries,
  seeded random words, invalid numeric byte
  limbs, and surrounding main/alt-stack state.
- **Execution class:** `unclassified`; the local helper uses tapscript context
  and no Bitcoin Core differential validation has been performed.

NOR reuses the existing OR table and adds four fused `255 - result` operations.
It is a fragment, so callers still provide numeric range checks, canonical
ScriptNum checks, terminal predicates, clean-stack handling, and transaction
validation where required.

The representative 0x01234567/0x89abcdef boundary is recorded as 346
locking-script bytes with a 272-item combined peak. The metric test
`u32_nor_metrics_are_current` checks the final script and static non-push count;
the latter is not an executed-opcode measurement.

See the [u32 implementation README](../../src/arithmetic/u32/README.md), the
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u32-nor`.
