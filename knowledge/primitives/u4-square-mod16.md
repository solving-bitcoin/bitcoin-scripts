# Checked u4 squaring modulo 16

`arithmetic::u4::square::u4_square_mod16` range-checks one u4 value and
selects `value^2 mod 16` from a generated 16-item table. It specializes the
generic two-input modulo-16 product for the equal-operand case.

## Research question

Can a square-specific lookup reduce the table state and witness shape for a
quadratic u4 operation? The representative construction uses one
witness-controlled value and a reusable 16-item table, while a generic
two-input u4 product needs 256 result entries.

## Contract and threat model

The caller pushes the table with `u4_push_square_table()` and invokes the
query:

```text
preserved | table[16] | value -> preserved | table[16] | (value^2 mod 16)
```

The query proves `value` is in `0..=15` before using it as an `OP_PICK`
index. A hostile value outside that numeric range fails. Numeric range
validation does not establish a byte-unique ScriptNum encoding, so callers
that need canonical bytes must bind that property separately. The table stays
on the combined stack until the caller drops or reuses it.

No witness hints are required: the representative boundary has one data item
and zero incremental hint items.

## Measurement

The query row excludes witness pushes and table setup, but includes the range
check and lookup. Stack measurement includes one input, the 16 table items,
the query's temporary items, and table cleanup. The local strict executor runs
the fragment in tapscript context with the combined 1,000-item stack limit.

| Configuration | Query script | Table setup | Witness | Data items | Hints | Peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `u4_square_mod16()` | 6 | 16 | 3 bytes | 1 | 0 | 20 | 4 |

The result is `locally-reproduced` by the focused metric fixture and CI run.

## Comparison and limitations

The square specializes equal operands: it needs 16 table entries and one data
item, rather than the 256 entries and two data items of a generic product.
It is not a replacement for multiplication of two independent witness values.
Table setup still consumes script bytes and combined stack capacity. This is a
fragment, not a complete locking script; terminal predicates, clean-stack
behavior, and any canonical encoding boundary remain with the caller.

There is no independent cryptographic security claim and no Bitcoin Core
consensus or relay-policy validation. The execution class is `unclassified`.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-square-mod16`.
