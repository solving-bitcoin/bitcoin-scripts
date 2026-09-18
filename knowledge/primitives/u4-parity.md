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

## Canonical witness adapter

The canonical variant answers whether the same 16-item parity table can bind
minimal ScriptNum encodings without changing the output contract. It replaces
only the per-item numeric check with `verify_canonical_nibble()`. At 32
hostile witness nibbles it costs 504 bytes, 65 serialized witness bytes, 51
combined stack items, and 360 static non-push opcodes, versus 440 bytes and 50
items for the numeric-only form. The canonical standalone batch range is
`1..=981`, while the numeric-only form reaches `1..=982`; the extra validator
item changes the peak from `n + 18` to `n + 19`. Compositions must leave
`n + 19 + unrelated_live_items <= 1000`, counting both stacks.

The threat model treats every nibble as hostile raw ScriptNum data. The
canonical variant rejects redundant sign bytes and negative zero as well as
negative and out-of-range values. The fragment-only boundary includes table
setup, canonical checks, queries, cleanup, and output restoration; it excludes
witness pushes, terminal predicates, unrelated live state, and transaction
context. Evidence is `locally-reproduced` and deployment remains
`unclassified`.

This is a projection fragment, not a complete locking script: callers still
need a terminal predicate and any required clean-stack or encoding binding.
The range check protects the lookup index but does not establish a byte-unique
ScriptNum encoding.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-parity`.
