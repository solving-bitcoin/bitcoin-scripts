# Checked u4 XOR reduction

## Research question

Can a checked batch of canonical u4 limbs be reduced to one nibble with a
reusable full XOR table, when the protocol needs a compact nibble checksum
instead of one output bit per input?

## Construction and threat model

`u4_nibbles_to_xor(nibble_count)` range-checks every hostile input in
`0..=15`, installs the existing 16x16 XOR table, folds the batch pairwise,
and removes the table before returning one nibble. No hints are used and no
cryptographic security claim is made.

## Boundary and comparison

The `fragment-with-memory` boundary includes input range checks, full-table
setup and cleanup, pairwise XOR reduction, and output routing. It excludes
witness pushes, terminal predicates, unrelated live state, and transaction
framing. The representative fixture uses 16 data items because a full table
is expensive; it is compared with the existing per-item parity projection,
which returns 16 bits rather than one four-bit aggregate.

| Construction | Locking script | Witness | Data items | Hint items | Peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| XOR reduction, 16 nibbles | 740 | 33 bytes | 16 | 0 | 273 | 438 |
| Parity projection, 32 nibbles | 440 | 65 bytes | 32 | 0 | 50 | 328 |

The XOR reduction is an output-cardinality adapter, not a general byte-cost
optimization. Parity is smaller when one bit per input is sufficient; this
primitive is useful when downstream logic consumes one nibble checksum.

## Evidence and execution class

The implementation and metrics are currently `locally-reproduced`; CI is the
executable reproduction gate. Deployment is `unclassified`. The full table
contributes 256 live items, and the 16-input fixture has a 273-item combined
main-plus-alt-stack peak. The batch limit reserves two temporary items under
the 1,000-item combined stack rule.

Static opcode count is not a dynamic execution or validation-weight claim. No
Bitcoin Core differential, relay-policy, or complete-transaction validation is
claimed.

## Stack contract

Before: `preserved | nibble[0] | ... | nibble[n-1]`, with the last input on
top and every input canonical.

After: `preserved | nibble[0] ^ ... ^ nibble[n-1]`. The input batch and lookup
table are consumed; unrelated main- and alt-stack state is preserved. The
fragment does not provide a terminal predicate or clean-stack wrapper.

## Reproduction

```sh
cargo test --locked arithmetic::u4::xor_reduce::tests --lib
cargo test --locked --test primitive_metrics u4_xor_reduce_metrics_are_current -- --exact
python3 tools/kb.py validate
```

The full repository test suite is intentionally not included in this focused
contribution run.
