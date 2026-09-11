# Checked u4 most-significant-bit projection

`arithmetic::u4::msb::u4_nibbles_to_msb` consumes a contiguous batch of
canonical four-bit limbs, proves each value is in `0..=15`, and replaces it
with its most-significant bit. It avoids materializing the other three bits
when a sign or magnitude branch needs only that bit.

- **Input:** `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
  on top.
- **Output:** `preserved | msb[0] | ... | msb[n-1]`, with the last bit on top.
- **Evidence:** `locally-reproduced` by all-nibble ordering tests, malformed
  input tests, batch-size boundary tests, and a strict metric fixture.
- **Representative result:** 440 locking-script bytes, 65 serialized witness
  bytes across 32 data items, 50 combined stack items, and no hints. The
  fragment contains 328 static non-push opcodes; this is not an executed-opcode
  or deployment claim.
- **Execution class:** `unclassified`. The strict local executor uses a
  tapscript context and the combined stack limit; Bitcoin Core consensus and
  relay policy have not been differentially tested.

This is a projection fragment, not a complete locking script. Callers still
need any terminal predicate, clean-stack rule, and byte-unique ScriptNum
binding required by their protocol.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-msb`.
