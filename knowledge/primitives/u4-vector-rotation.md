# Checked u4 cyclic vector rotation

`arithmetic::u4::vector_rotate::u4_nibbles_rotate_left` consumes a contiguous
checked u4 vector and rotates its stack order by one position:

```text
nibble[0] ... nibble[n-1] -> nibble[1] ... nibble[n-1] nibble[0]
```

This is a stack-scheduling primitive for protocols that consume a fixed-width
nibble state cyclically. It changes ordering only; it does not change any
nibble value.

## Contract

```text
preserved | nibble[0] ... nibble[n-1]
    -> preserved | nibble[1] ... nibble[n-1] nibble[0]
```

The input vector must be nonempty. Every source item is range-checked as
`0..=15` before it is copied, and all pre-existing main- and altstack items are
preserved. The implementation stages the rotated copies on the altstack,
removes the original vector, then restores the new order.

## Measurement

The representative row includes 32 numeric range checks, all 32 stack copies,
input cleanup, and output restoration. It excludes witness pushes, terminal
predicates, unrelated live state, and transaction context.

| Configuration | Script | Witness | Data items | Hints | Peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `u4_nibbles_rotate_left(32)` | 457 bytes | 65 bytes | 32 | 0 | 64 | 303 |

The measurements are `locally-reproduced` by the primitive metric fixture.
Static non-push opcodes are a serialized-script count, not a dynamic execution
count. The standalone generator ceiling is 499 input nibbles before unrelated
stack state is accounted for. No cryptographic security claim is made.

## Comparison

The operation is smaller than a general-purpose transpose because it has a
single fixed cycle and needs no lookup table. It is not a value transformation,
canonicality boundary, or commitment: callers must bind the intended vector
length and use a terminal predicate at the surrounding fragment boundary.
Existing `u4::rotate` helpers rotate bits within numeric words; this primitive
rotates the order of vector items and has a different stack contract.

## Validation

Focused tests cover ordinary rotation, singleton identity, malformed nibbles,
batch boundaries, and preservation of unrelated main and altstack items. Run:

```sh
cargo test --locked arithmetic::u4::vector_rotate
cargo test --locked --test primitive_metrics u4_vector_rotate_metrics_are_current
python3 tools/kb.py validate
```

Execution remains `unclassified`: the local strict executor measures combined
stack occupancy, but no Bitcoin Core consensus or relay-policy transaction has
validated this fragment.
