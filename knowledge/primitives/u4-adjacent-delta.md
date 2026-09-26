# Checked u4 adjacent forward delta

`arithmetic::u4::adjacent_delta::u4_nibbles_to_adjacent_delta` consumes a
contiguous checked u4 vector and returns the forward difference of each edge:

```text
delta[i] = (nibble[i + 1] - nibble[i]) mod 16
```

The operation is useful as a small sequence adapter for nibble-oriented
encodings. Equal adjacent symbols become zero deltas, while wraparound remains
inside the canonical u4 domain without a lookup table.

## Contract

```text
preserved | nibble[0] ... nibble[n-1]
    -> preserved | delta[0] ... delta[n-2]
```

The input vector must contain at least two numeric nibbles. Every input is
range-checked as `0..=15`; the output is a numeric ScriptNum in the same range.
The initial nibble is not returned, so the transform is not invertible unless a
caller retains that value separately.

## Measurement

The representative row includes all input range checks, the direct subtraction
and wraparound normalization for 31 edges, input cleanup, and output
restoration. It excludes witness pushes, the initial-value binding required for
inversion, terminal predicates, unrelated live state, and transaction context.

| Configuration | Script | Witness | Data items | Hints | Peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `u4_nibbles_to_adjacent_delta(32)` | 806 bytes | 65 bytes | 32 | 0 | 65 | 547 |

The numbers are `locally-reproduced` by the primitive metric fixture; static
non-push opcodes are a serialized-script count, not a dynamic execution count.
The standalone generator ceiling is 499 input nibbles before unrelated stack
state is accounted for. The fragment uses no witness hints and has no
independent cryptographic-security claim.

## Comparison

The transform preserves more information than an adjacent-equality mask or a
transition count, but costs one output nibble per input edge. It is not a
replacement for a checksum or commitment: retaining the first nibble is an
additional caller obligation, and a terminal predicate remains outside this
fragment. Compared with a table-based u4 XOR delta, this construction avoids a
resident lookup table at the cost of a conditional normalization branch per
edge.

## Validation

Focused tests cover ordinary deltas, equal pairs, modulo-16 wraparound,
malformed nibbles, batch boundaries, and preservation of unrelated main and
altstack items. Run:

```sh
cargo test --locked arithmetic::u4::adjacent_delta
cargo test --locked --test primitive_metrics u4_adjacent_delta_metrics_are_current
python3 tools/kb.py validate
```

Execution remains `unclassified`: the local strict executor measures combined
stack occupancy, but no Bitcoin Core consensus or relay-policy transaction has
validated this fragment.
