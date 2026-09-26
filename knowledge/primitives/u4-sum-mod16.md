# Checked u4 modulo-16 sum

## Research question

Can a contiguous batch of hostile u4 limbs be reduced to one modulo-16
checksum with a reusable table, without expanding the batch into bits or
requiring disabled arithmetic opcodes? The comparison objective is a compact
checksum/routing boundary for nibble-oriented protocols.

## Semantics and boundary

`arithmetic::u4::sum::u4_nibbles_to_sum_mod16(n)` consumes
`nibble[0] ... nibble[n-1]`, with `nibble[n-1]` on top, and returns:

```text
(nibble[0] + ... + nibble[n-1]) mod 16
```

Every input must be a minimally encoded ScriptNum in `0..=15`. The reduction
uses a 31-item table for sums `0..=30`; the accumulator remains in `0..=15`
after each lookup. The table is removed before the result is returned, and
unrelated main- and altstack items are preserved.

The threat model treats every witness nibble as hostile, including raw
noncanonical encodings. No hint items or cryptographic security claim are
involved. The fragment is not a complete locking script and supplies no
terminal clean-stack predicate.

## Evidence and cost

The result is `locally-reproduced` with deterministic boundary and mixed-batch
tests, invalid numeric values in every position, noncanonical zero encodings,
batch-size guards, and strict local tapscript execution.

| Configuration | Script | Witness | Data items | Hint items | Combined peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 32 checked nibbles, all `7` | 592 bytes | 65 bytes | 32 | 0 | 66 | 400 |

The table has 31 persistent items. The conservative generator bound is 965
nibbles before unrelated live state is counted; the representative boundary
uses 32 items. Dynamic opcode count and validation weight are unavailable from
the local executor. Deployment remains `unclassified`: Bitcoin Core consensus,
relay policy, and complete transaction framing were not tested.

## Closest comparison

The existing `u4_nibbles_to_parity(32)` and `u4_nibbles_to_lsb(32)` projections
cost 440 bytes with a 16-item table, but they preserve one output per input.
This reducer costs 592 bytes because it validates and folds every input into a
single accumulator while indexing a 31-entry modulo table. It is useful when a
caller needs one additive checksum rather than a vector of projections; it is
not a replacement for those projections.

## Reproduction

```sh
cargo test --locked 'arithmetic::u4::sum::tests' --lib
cargo test --locked --test primitive_metrics u4_sum_metrics_are_current
python3 tools/kb.py validate
```
