# Checked public-constant u4 multiplication modulo 16

`arithmetic::u4::mul_constant::u4_mul_constant_mod16` range-checks one u4
value and selects `constant * value mod 16` from a generated 16-item table.
The constant is public and fixed when the locking script is compiled; the
input remains witness data.

## Research question

Can a one-dimensional public-constant table provide a reusable checked u4
product with less table state than a general two-input u4 multiplication
table? The representative experiment uses `constant = 10` and compares the
16-item table boundary with the 256-item table required by generic u4
multiplication.

## Contract and threat model

The caller pushes a table with `u4_push_mul_constant_table(10)` and then
invokes the query:

```text
preserved | table[16] | value -> preserved | table[16] | (10*value mod 16)
```

The query proves `value` is in `0..=15` before using it as an `OP_PICK`
index. A hostile value outside that numeric range fails. A numeric range check
does not establish a byte-unique ScriptNum encoding, so callers that need that
property must bind canonical encodings separately. The table and output remain
on the combined stack until the caller drops or reuses them.

No witness hints are required: the representative boundary has one data item
and zero incremental hint items. The constant is not witness-controlled.

## Measurement

The query row excludes witness pushes and table setup, but includes the range
check and lookup. Stack measurement includes one input, the 16 table items, the
query's temporary items, and table cleanup. The local strict executor runs the
fragment in tapscript context with the combined 1,000-item stack limit.

| Configuration | Query script | Table setup | Witness | Data items | Hints | Peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `u4_mul_constant_mod16`, `constant=10` | 6 | 16 | 3 bytes | 1 | 0 | 20 | 4 |

The result is `locally-reproduced` by the focused metric fixture and CI run.

## Comparison and limitations

The construction is useful when the multiplier is public and reused: its
lookup table has 16 entries, while a generic two-input modulo-16 product needs
256 result entries. It does not replace generic multiplication when both
operands are witness-controlled, and table setup still consumes script bytes
and combined stack capacity. This is a fragment, not a complete locking
script; terminal predicates, clean-stack behavior, and any canonical encoding
boundary remain with the caller.

There is no independent cryptographic security claim and no Bitcoin Core
consensus or relay-policy validation. The execution class is `unclassified`.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-mul-constant-mod16`.
