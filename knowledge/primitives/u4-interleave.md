# Checked u4 vector interleave

`arithmetic::u4::interleave::u4_nibbles_interleave` consumes two equal-width,
range-checked u4 vectors and alternates their items:

```text
left[0] ... left[n-1] | right[0] ... right[n-1]
    -> left[0] right[0] ... left[n-1] right[n-1]
```

It is a stack-scheduling primitive for paired lanes, transcript fields, and
other consumers that need adjacent values from two independently produced
vectors.

## Contract

```text
preserved | left[0] ... left[n-1] | right[0] ... right[n-1]
    -> preserved | left[0] right[0] ... left[n-1] right[n-1]
```

Both vectors must have the declared nonzero width. Every input is range-checked
as `0..=15` before copying. The original vectors are kept on the main stack
while the alternating output is staged on the altstack; pre-existing state is
preserved.

## Measurement

The representative row includes 64 numeric range checks, 64 stack copies, input
cleanup, and output restoration for two 32-wide vectors. It excludes witness
pushes, terminal predicates, unrelated live state, and transaction context.

| Configuration | Script | Witness | Data items | Hints | Peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `u4_nibbles_interleave(32)` | 954 bytes | 129 bytes | 64 | 0 | 128 | 608 |

The measurements are `locally-reproduced` by the primitive metric fixture.
Static non-push opcodes are a serialized-script count, not a dynamic execution
count. The standalone generator ceiling is 249 items per vector before
unrelated stack state is accounted for. No cryptographic security claim is
made.

## Comparison

Interleaving is smaller and simpler than a general permutation because it has a
fixed two-lane pattern, but it temporarily retains four vector-widths of stack
state. It is not a serialization or commitment boundary: callers must bind the
width, item encoding, and terminal predicate at the surrounding fragment.

## Validation

Focused tests cover ordinary paired ordering, singleton vectors, malformed
nibbles, width boundaries, and preservation of unrelated main and altstack
items. Run:

```sh
cargo test --locked arithmetic::u4::interleave
cargo test --locked --test primitive_metrics u4_interleave_metrics_are_current
python3 tools/kb.py validate
```

Execution remains `unclassified`: the local strict executor measures combined
stack occupancy, but no Bitcoin Core consensus or relay-policy transaction has
validated this fragment.
