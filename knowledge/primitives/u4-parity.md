# Checked u4 parity projection

`arithmetic::u4::parity::u4_nibbles_to_parity` consumes a contiguous batch of
numeric nibbles, proves each value is in `0..=15`, and replaces it with one
numeric parity bit. It uses a 16-item generated lookup table, so it is useful
when a protocol needs parity but not the four expanded bits.

- **Input:** `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
  on top.
- **Output:** `preserved | parity[0] | ... | parity[n-1]`, with the last bit
  on top.
- **Evidence:** `locally-reproduced` by exhaustive nibble tests, malformed-input
  tests, and a strict metric fixture.
- **Representative result:** 440 locking-script bytes, 65 serialized witness
  bytes for 32 one-byte data items, 50 combined stack items, and no hints for a
  32-nibble batch. The fragment contains 328 static non-push opcodes; that is
  not an executed-opcode or deployment claim.
- **Execution class:** `unclassified`. The local strict executor runs the
  fragment in tapscript context with the combined stack limit; no Bitcoin Core
  consensus or relay-policy transaction has been tested.

This is a projection fragment, not a complete locking script: callers still
need a terminal predicate and any required clean-stack or encoding binding.
The range check protects the lookup index but does not establish a byte-unique
ScriptNum encoding.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-parity`.
