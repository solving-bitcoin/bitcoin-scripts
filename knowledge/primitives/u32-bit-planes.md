# Checked u32 bit-plane transpose

`arithmetic::u32::bits::u32_to_bit_planes` consumes one u32 represented by
four canonical byte limbs and emits eight numeric 4-bit planes. Plane zero is
the most-significant bit across the four bytes; plane seven is on top of the
returned stack.

## Research question

Can a checked byte-oriented u32 word be transposed into eight composable
nibbles while keeping the combined stack peak below a full 32-bit-item
representation?

The hypothesis is that reusing the existing byte-to-bit converter and routing
one bit from each byte lane per plane will cost more locking bytes than the
plain bit adapter but substantially reduce the output item count for bit-sliced
nibble consumers.

- **Input:** `byte[0] | byte[1] | byte[2] | byte[3]`, most significant byte
  first, with the least significant byte on top.
- **Output:** eight numeric nibbles, plane zero deepest and plane seven on top;
  each plane's high bit comes from `byte[0]`.
- **Evidence:** `locally-reproduced` by zero, all-one, structured-pattern, and
  noncanonical-witness tests, plus a strict metric fixture.
- **Representative result:** 877 locking-script bytes, 9 serialized witness
  bytes across four `0x42` data items (13-byte maximum canonical fixture), 45
  combined stack items, and no hints. The fragment contains 628 static
  non-push opcodes; this is not an executed opcode or deployment claim.
- **Execution class:** `unclassified`. The strict local executor uses a
  tapscript context and the combined stack limit; Bitcoin Core consensus and
  relay policy have not been differentially tested.

The comparison boundary is the fragment only: input pushes, terminal
predicates, unrelated stack state, and transaction context are excluded. The
threat model treats all four byte limbs and their raw witness encodings as
hostile; every limb is checked for canonical byte encoding before conversion.
The output nibbles are generated values, not an authorization predicate.

The closest existing construction is `u32_to_le_bits()`, which is 514 bytes
and peaks at 35 items while returning 32 individual bits. The transpose is a
deliberate composability trade: it costs 363 more bytes and 10 more peak items
to return eight nibbles. A direct per-plane altstack loop was rejected because
restoring each shifted lane to the altstack top rereads the same lane; the
published version uses a stable 32-bit source stack and fixed-depth copies.

See the [implementation README](../../src/arithmetic/u32/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u32-bit-planes`.
