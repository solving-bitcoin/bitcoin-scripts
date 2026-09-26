# Checked u4 centered-signed projection

`arithmetic::u4::centered::u4_nibbles_to_centered` consumes a contiguous batch
of canonical u4 nibbles and maps each value to a balanced signed digit:

```text
centered(x) = x       for 0 <= x <= 7
               x - 16 for 8 <= x <= 15
```

- **Input:** `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
  on top.
- **Output:** `preserved | centered[0] | ... | centered[n-1]`, with the last
  signed digit on top and each digit in `-8..=7`.
- **Evidence:** `locally-reproduced` by exhaustive 16-value tests,
  malformed-input and batch-boundary tests, and a strict metric fixture.
- **Representative result:** 447 locking-script bytes, 65 serialized witness
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

Can a checked u4-to-balanced-digit adapter expose a signed representation for
downstream arithmetic without expanding the stack or adding witness hints? The
hypothesis is that a 16-entry generated table can provide the centered domain
with the same 50-item peak and only a small literal-cost delta. The comparison
objective is the closest unsigned u4 projections and the repository's wider
balanced-digit backends under the same fragment-only boundary.

The threat model treats every input ScriptNum as hostile: values outside
`0..=15` must fail before `OP_PICK`, while non-minimal encodings remain outside
this fragment's claims. Hard constraints are the 1,000-item combined
main/alt-stack limit, deterministic table generation, no witness hints, and no
consensus or relay-policy assumption. Execution is therefore `unclassified`.

The centered mapping is useful for signed carry and difference compositions,
but it does not itself prove a complete bounded integer representation. Callers
must enforce any downstream digit bound, carry relation, terminal predicate,
and clean-stack contract.

Run:

```sh
cargo test --locked arithmetic::u4::centered
cargo test --locked --test primitive_metrics u4_centered_metrics_are_current
python3 tools/kb.py validate
```
