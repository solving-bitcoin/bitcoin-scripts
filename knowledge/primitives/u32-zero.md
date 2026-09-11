# Checked u32 zero predicate

`arithmetic::u32::zero::u32_iszero` consumes a u32 represented by four numeric
byte limbs, checks each limb's byte range, and returns one numeric Boolean for
whether the word is zero. It uses no lookup table.

- **Input:** four byte-valued limbs, most significant byte first, with the
  least significant byte on top.
- **Output:** one numeric Boolean ScriptNum.
- **Evidence:** `locally-reproduced` by zero, nonzero, boundary, and malformed
  byte tests plus a strict metric fixture.
- **Representative result:** 53 locking-script bytes, 13 serialized witness
  bytes across four data items, 6 combined stack items, and no hints. The
  fragment contains 37 static non-push opcodes; this is not an executed-opcode
  or deployment claim.
- **Execution class:** `unclassified`. The strict local executor uses a
  tapscript context and the combined stack limit; Bitcoin Core consensus and
  relay policy have not been differentially tested.

This is a fragment rather than a complete locking script. Callers still need
any terminal predicate, clean-stack rule, and byte-unique ScriptNum binding
required by their protocol.

See the [implementation README](../../src/arithmetic/u32/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u32-zero`.
