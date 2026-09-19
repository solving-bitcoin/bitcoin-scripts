# Checked u4 most-significant-bit projection

`arithmetic::u4::msb::u4_nibbles_to_msb` range-checks each numeric nibble and
replaces it with the bit `nibble >= 8`. It uses a direct threshold rather than
a lookup table.

- **Input:** `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
  on top; every nibble must be in `0..=15`.
- **Output:** `preserved | msb[0] | ... | msb[n-1]`, with the last bit on top.
- **Evidence:** `locally-reproduced` by boundary, malformed-input, and strict
  stack-frontier tests plus a metric fixture.
- **Representative result:** 446 locking-script bytes, 65 serialized witness
  bytes, 34 combined stack items, and 350 static non-push opcodes for 32
  checked nibbles. This is not an executed-opcode or deployment claim.
- **Execution class:** `unclassified`; the local strict executor uses
  tapscript context and the combined stack limit, not Bitcoin Core consensus
  or relay-policy validation.

The standalone direct-threshold schedule peaks at `n + 2` items and accepts
`1..=998`; callers must reduce the width for unrelated live main- or alt-stack
state. Numeric range checking does not establish canonical or byte-unique
ScriptNum encodings, and this projection is not a complete locking script:
callers still need a terminal predicate and any required clean-stack binding.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-msb`.
