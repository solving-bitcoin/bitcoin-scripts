# Checked u4 complement-reflection projection

`arithmetic::u4::mirror::u4_nibbles_to_mirror` consumes a contiguous batch of
canonical u4 nibbles and maps each complement-symmetric pair to one
representative:

```text
mirror(x) = min(x, 15 - x)
```

- **Input:** `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
  on top.
- **Output:** `preserved | mirror[0] | ... | mirror[n-1]`, with the last
  representative on top and each output in `0..=7`.
- **Evidence:** `locally-reproduced` by exhaustive 16-value tests,
  malformed-input and batch-boundary tests, and a strict metric fixture.
- **Representative result:** 440 locking-script bytes, 65 serialized witness
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

Can a checked quotient under the involution `x ↔ 15-x` reduce a four-bit symbol
to a canonical seven-value domain without increasing the one-item stack shape?
The hypothesis is that the existing 16-entry lookup schedule can provide this
symmetry quotient at the same measured cost as parity and LSB projections. The
comparison objective is the closest bit projections and the unquotiented u4
representation under the same fragment-only boundary.

The threat model treats every input ScriptNum as hostile: values outside
`0..=15` must fail before `OP_PICK`, while non-minimal encodings remain outside
this fragment's claims. Hard constraints are the 1,000-item combined
main/alt-stack limit, deterministic table generation, no witness hints, and no
consensus or relay-policy assumption. Execution is therefore `unclassified`.

The mapping deliberately loses the complement-orientation bit. It is only
appropriate when the downstream relation is invariant under that symmetry; it
is not a reversible encoding or a complete equality test for original nibbles.

Run:

```sh
cargo test --locked arithmetic::u4::mirror
cargo test --locked --test primitive_metrics u4_mirror_metrics_are_current
python3 tools/kb.py validate
```
