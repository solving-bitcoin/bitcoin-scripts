# Checked u32 byte extraction

`arithmetic::u32::stack::u32_extract_byte(index)` consumes a u32 represented
by four numeric byte limbs and returns one selected byte. The index is fixed at
script-construction time: `0` is the most significant byte and `3` is the least
significant byte.

## Research question

Can a fixed-index byte-lane adapter validate and route one byte from a u32 word
without a lookup table or a dynamic selector?

The hypothesis is that validating the four limbs once and using stack routing
is smaller and safer for fixed protocol fields than converting the entire word
to bits or constructing a byte lookup table.

- **Input:** `byte[0] | byte[1] | byte[2] | byte[3]`, most significant byte
  first, with the least significant byte on top.
- **Output:** the selected canonical numeric byte; the other three limbs are
  consumed.
- **Evidence:** `locally-reproduced` by all four index cases, boundary values,
  invalid-limb tests in every position, and a strict metric fixture for index
  `0`.
- **Representative result:** 56 locking-script bytes, 13 serialized witness
  bytes across four `0xff` data items, 7 combined stack items, and no hints.
  The index-0 fragment contains 36 static non-push opcodes; this is not an
  executed opcode or deployment claim.
- **Execution class:** `unclassified`. The strict local executor uses a
  tapscript context and the combined stack limit; Bitcoin Core consensus and
  relay policy have not been differentially tested.

The comparison boundary is the fragment only: input pushes, terminal
predicates, unrelated stack state, and transaction context are excluded. The
threat model treats every limb and raw witness encoding as hostile; all four
limbs are range-checked before routing. The caller still owns byte-unique
ScriptNum binding and clean-stack behavior.

A dynamic-index selector was deliberately not included: it needs an additional
selector contract and a separate routing cost. A lookup-table implementation
is dominated for this fixed four-way extraction and is not composable with the
same byte-only contract.

See the [implementation README](../../src/arithmetic/u32/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u32-extract-byte`.
