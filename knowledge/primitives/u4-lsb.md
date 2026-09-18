# Checked u4 least-significant-bit projection

`arithmetic::u4::lsb::u4_nibbles_to_lsb` consumes a contiguous batch of
four-bit limbs, proves each value is in `0..=15`, and replaces it
with its least-significant bit. It avoids materializing the other three bits
when a bit-oriented encoding needs only the low bit.

- **Input:** `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
  on top.
- **Output:** `preserved | lsb[0] | ... | lsb[n-1]`, with the last bit on top.
- **Evidence:** `locally-reproduced` by all-nibble ordering tests, malformed
  input tests, batch-size boundary tests, and a strict metric fixture.
- **Representative result:** 440 locking-script bytes, 65 serialized witness
  bytes across 32 data items, 50 combined stack items, and no hints. The
  fragment contains 328 static non-push opcodes; this is not an executed-opcode
  or deployment claim.
- **Execution class:** `unclassified`. The strict local executor uses a
  tapscript context and the combined stack limit; Bitcoin Core consensus and
  relay policy have not been differentially tested.

## Canonical witness adapter

The research question is whether the existing 16-item LSB table can bind
byte-unique ScriptNum encodings without changing the projection contract. The
canonical variant reuses the same table and replaces only the per-item numeric
check with `verify_canonical_nibble()`. For 32 hostile witness nibbles it costs
504 bytes, 65 serialized witness bytes, 51 combined stack items, and 360
static non-push opcodes. The ordinary range-checked form remains 440 bytes and
50 items when a caller already owns canonical limbs. The canonical standalone
batch range is `1..=981`, while the ordinary form reaches `1..=982`; the extra
canonical check adds one stack item to the per-input peak. Compositions must
leave `n + 19 + unrelated_live_items <= 1000`, counting both stacks.

The threat model treats every nibble as hostile raw ScriptNum data. The
canonical variant rejects redundant sign bytes and negative zero in addition
to negative and out-of-range values. Its fragment-only boundary includes the
16-item table, canonical checks, queries, cleanup, and output restoration; it
excludes witness pushes, terminal predicates, unrelated live state, and
transaction context. Deterministic tests cover all nibble values, malformed
encodings at every position, and surrounding main/alt-stack preservation.
Evidence is `locally-reproduced`; deployment remains `unclassified`.

This is a projection fragment, not a complete locking script. Callers still
need any terminal predicate, clean-stack rule, and byte-unique ScriptNum
binding required by their protocol.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-lsb`.
