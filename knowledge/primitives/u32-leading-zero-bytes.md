# Checked u32 leading zero-byte count

`arithmetic::u32::stack::u32_leading_zero_bytes` consumes one u32 represented
by four numeric byte limbs and returns the number of zero limbs before the
first nonzero limb.

## Research question

Can a fixed-width u32 prefix classifier return the number of leading zero bytes
without a lookup table while preserving strict hostile-limb validation?

The hypothesis is that four nested branches are smaller and less stack-heavy
than reusing the 256-entry byte table used by population count, while remaining
useful for fixed-width prefix or wire-format decisions.

- **Input:** `byte[0] | byte[1] | byte[2] | byte[3]`, most significant byte
  first, with the least significant byte on top.
- **Output:** one numeric ScriptNum in `0..=4`.
- **Evidence:** `locally-reproduced` by boundary tests, malformed-limb tests
  covering every position including limbs after the first nonzero byte, and a
  strict metric fixture.
- **Representative result:** 159 locking-script bytes, 13 serialized witness
  bytes across four `0xff` data items, 7 combined stack items, and no hints.
  The fragment contains 104 static non-push opcodes; this is not an executed
  opcode or deployment claim.
- **Execution class:** `unclassified`. The strict local executor uses a
  tapscript context and the combined stack limit; Bitcoin Core consensus and
  relay policy have not been differentially tested.

The comparison boundary is the fragment only: input pushes, the caller's
terminal predicate, unrelated stack state, and transaction context are
excluded. The threat model treats every limb and every raw witness encoding as
hostile; numeric byte range and minimal ScriptNum encoding are checked before a
limb is consumed.

The construction validates every limb, then counts from most significant to
least significant. Once the count is determined, all remaining limbs are
validated and dropped. It is table-free and can support prefix-length or
wire-format decisions, but it does not establish a byte-unique ScriptNum
encoding or supply a terminal predicate and clean-stack rule for its caller.

See the [implementation README](../../src/arithmetic/u32/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u32-leading-zero-bytes`.
