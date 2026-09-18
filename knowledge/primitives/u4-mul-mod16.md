# Checked modulo-16 u4 multiplication

## Research question

Can two hostile canonical u4 limbs be multiplied modulo 16 with one reusable
256-entry table, while keeping the lookup index range-checked and preserving a
simple table-resident composition boundary?

## Construction and threat model

`u4_mul_mod16()` checks both inputs in `0..=15`, forms the row-major index
`16*a+b`, and selects `(a*b) mod 16` from a table below the inputs. The table
is explicit and reusable; no witness hints are used. Inputs are hostile and
out-of-range values must fail before table indexing. No cryptographic security
claim is made.

## Boundary and comparison

The fragment boundary includes both numeric range checks, index formation, and
the product lookup. It excludes table setup and cleanup, terminal predicates,
transaction context, and unrelated caller state. The closest existing u4
arithmetic construction is table-backed addition: multiplication needs a full
256-entry table rather than the smaller addition quotient/modulo tables.

| Construction | Locking script | Witness | Data items | Hint items | Peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Checked product modulo 16 | pending focused CI metric | 5 bytes | 2 | 0 | pending focused CI metric | pending focused CI metric |

The table contains 256 items and remains below the returned product so callers
can amortize setup across repeated products or remove it explicitly. The
result is expected to be useful only when a modulo-16 product is needed and
the surrounding protocol can afford the resident table.

## Evidence and execution class

The implementation is currently `inspected`; focused CI is the executable
reproduction gate. Deployment is `unclassified`. The local helper runs in a
tapscript context with the strict combined stack limit; this is not Bitcoin
Core consensus or relay-policy validation.

Static opcode count is not a dynamic execution or validation-weight claim. No
cryptographic or deployability claim is made.

## Stack contract

Before: `... | product_table | a | b`, where `a` and `b` are numeric nibbles.

After: `... | product_table | (a*b mod 16)`. The two operands are consumed and
the table remains available for reuse. Callers may remove it with
`u4_drop_full_product_table()`.

## Reproduction

```sh
cargo test --locked arithmetic::u4::mul::tests --lib
cargo test --locked --test primitive_metrics u4_mul_mod16_metrics_are_current -- --exact
python3 tools/kb.py validate
```

The full repository test suite is intentionally not included in this focused
contribution run.
