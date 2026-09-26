# Checked u32 trailing zero-byte count

`arithmetic::u32::stack::u32_trailing_zero_bytes` consumes one u32 represented
by four numeric byte limbs and returns the number of zero limbs after the last
nonzero limb.

## Research question

Can a fixed-width u32 suffix classifier use the module's native top-limb order
to count trailing zero bytes without a lookup table while preserving strict
hostile-limb validation?

The hypothesis is that direct stack branching is smaller than a reusable
256-entry byte table and avoids the altstack routing needed when scanning from
the most significant side.

- **Input:** `byte[0] | byte[1] | byte[2] | byte[3]`, most significant byte
  first, with the least significant byte on top.
- **Output:** one numeric ScriptNum in `0..=4`.
- **Evidence:** `locally-reproduced` by boundary tests, invalid-limb tests in
  every position, noncanonical witness tests, and a strict metric fixture.
- **Representative result:** 147 locking-script bytes, 13 serialized witness
  bytes across four `0xff` data items, 7 combined stack items, and no hints.
  The fragment contains 92 static non-push opcodes; this is not an executed
  opcode or deployment claim.
- **Execution class:** `unclassified`. The strict local executor uses a
  tapscript context and the combined stack limit; Bitcoin Core consensus and
  relay policy have not been differentially tested.

The comparison boundary is the fragment only: input pushes, the caller's
terminal predicate, unrelated stack state, and transaction context are
excluded. The threat model treats every limb and raw witness encoding as
hostile. Each limb is checked before it is consumed, including limbs remaining
after the first nonzero byte determines the count.

This is a suffix classifier for little-endian wire-format or length decisions,
not a zero predicate or a complete byte-unique ScriptNum encoding. The caller
still supplies any terminal predicate and clean-stack rule.

See the [implementation README](../../src/arithmetic/u32/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u32-trailing-zero-bytes`.
