# Checked u4 one-hot mask projection

`arithmetic::u4::one_hot::u4_nibbles_to_one_hot` consumes a contiguous batch of
numeric nibbles, proves each value is in `0..=15`, and replaces it with the
numeric selector mask `1 << nibble`. The result keeps one stack item per input
while making the 16 categories explicit for selector and membership-mask
compositions.

- **Input:** `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
  on top.
- **Output:** `preserved | mask[0] | ... | mask[n-1]`, with the last mask on
  top; each mask is in `1..=32768`.
- **Evidence:** `locally-reproduced` by exhaustive 16-value tests,
  malformed-input and batch-boundary tests, and a strict metric fixture.
- **Representative result:** 461 locking-script bytes, 65 serialized witness
  bytes for 32 one-byte data items, 50 combined stack items, and no hints. The
  fragment contains 328 static non-push opcodes; this is not a dynamic opcode
  or deployment claim.
- **Execution class:** `unclassified`; no Bitcoin Core consensus or relay-policy
  transaction has validated this fragment.

The generated 16-item table is kept on the main stack while each input is
range-checked and looked up, then removed before outputs are restored. The
standalone batch ceiling is 982 input items before unrelated stack state is
accounted for. Numeric range checks do not establish byte-unique ScriptNum
encoding, and the fragment does not provide a terminal predicate or clean-stack
guarantee.

## Research question and boundary

Can a checked one-hot representation make all 16 u4 categories selectable
without expanding each input into 16 stack items? The hypothesis is that a
single numeric mask per input preserves the one-item stack shape, with only a
small literal-serialization premium over parity/LSB. The comparison objective
is the closest u4 projections and bit-plane expansion under the same
fragment-only boundary.

The threat model treats every input ScriptNum as hostile: values outside
`0..=15` must fail before `OP_PICK`, while non-minimal encodings remain outside
this fragment's claims. Hard constraints are the 1,000-item combined
main/alt-stack limit, deterministic table generation, no witness hints, and no
consensus or relay-policy assumption. Execution is therefore `unclassified`.

Compared with four-bit expansion, one-hot masks use one output item per input
but carry a larger numeric value. Compared with parity or LSB, they retain a
distinct category for every nibble; the tradeoff is 21 extra script bytes at
the representative 32-input boundary because high masks need longer pushes.

Run:

```sh
cargo test --locked arithmetic::u4::one_hot
cargo test --locked --test primitive_metrics u4_one_hot_metrics_are_current
python3 tools/kb.py validate
```
