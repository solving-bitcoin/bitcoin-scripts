# Checked modulo-16 u4 multiplication

## Research question

Can two hostile numeric inputs be range-checked to `0..=15` and multiplied
modulo 16 with one reusable 256-entry table, while keeping the lookup index
range-checked and preserving a simple table-resident composition boundary?

## Construction and threat model

`u4_mul_mod16()` checks both numeric ScriptNum inputs in `0..=15`, forms the row-major index
`16*a+b`, and selects `(a*b) mod 16` from a table below the inputs. The table
is explicit and reusable; no witness hints are used. Inputs are hostile and
out-of-range values must fail before table indexing. The range checks establish
a numeric range, not byte-unique ScriptNum encoding; acceptance of non-minimal
aliases depends on the execution profile. A caller that needs byte-unique
encodings must add a canonical-encoding check. No cryptographic security claim
is made.

## Boundary and comparison

The fragment boundary includes both numeric range checks, index formation, and
the product lookup. It excludes table setup and cleanup, terminal predicates,
transaction context, and unrelated caller state. The closest existing u4
arithmetic construction is table-backed addition: multiplication needs a full
256-entry table rather than the smaller addition quotient/modulo tables.

| Construction | Locking script | Witness | Data items | Hint items | Peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Checked product modulo 16 | 21 | 5-byte representative 2-item data witness | 2 | 0 | 261 | 17 |

The fragment-only 21-byte query measurement excludes table setup and cleanup,
input pushes, terminal predicate, unrelated state, and transaction context.
The witness figure is the serialized two-item data vector used by the local
metric; it is not a complete Taproot witness. The table contains 256 items and
remains below the returned product so callers can amortize setup across
repeated products. The result must be moved or consumed before
`u4_drop_full_product_table()` is called; otherwise cleanup drops the result
instead of the table. The 5-byte witness is a representative fixture, not a
maximum when non-minimal numeric encodings are accepted. The query uses zero
incremental hint items; the table is script memory, not witness hints.

The focused suite runs all 256 operand pairs against an independent host
calculation, checks malformed values in both positions, and verifies the
resident table's values and order after all 256 queries and before dropping the
actual table. A full-leaf test stages every result, drops the table, verifies
all outputs and requires a single final true item. The main and altstack
sentinels are checked separately. That separate all-lifecycle script pushes
the operand pairs as script constants (zero external witness data and zero
hints) and reaches a measured 516-item combined main/altstack peak under the
strict local stack limit. This is not the one-query metric boundary and makes
no numeric maximum-composition claim; callers must account for all live data
and resident tables under the combined 1,000-item limit.

## Evidence and execution class

The implementation is `locally-reproduced` by focused local tests. Deployment is
`unclassified`. The local helper runs in a
tapscript context with the strict combined stack limit; this is not Bitcoin
Core consensus or relay-policy validation.

Static opcode count is not a dynamic execution or validation-weight claim. No
cryptographic or deployability claim is made.

The original implementation at commit
[`1a9c4c981d5369b8f69e04b884e5f7c36da232c6`](https://github.com/brenorb/bitcoin-scripts/commit/1a9c4c981d5369b8f69e04b884e5f7c36da232c6)
was reproduced with its then-current tests and lockfile. Its all-pairs positive
leaf check failed first for `[expected=0, a=0, b=0]` with
`InvalidStackOperation` at `OP_2DROP`. A test-only mutant preserves that exact
pre-fix `OP_DUP OP_ADD OP_ADD OP_ADD OP_ADD` index-building sequence (including
the surrounding swaps) and is rejected by the same shared positive-leaf
assertion. The repaired production fragment is at PR revision
[`35a9e8972ccb38767f1b00b51f71405d5033f1df`](https://github.com/solving-bitcoin/bitcoin-scripts/commit/35a9e8972ccb38767f1b00b51f71405d5033f1df).
The historical run used compiler `rust-bitcoin-script` `124b561e` and
interpreter `rust-bitcoin-scriptexec` `702544c9`; the current integrated tests
use the same compiler and interpreter `a09e87af`. These local runs do not
establish Bitcoin Core consensus or relay-policy acceptance.

## Stack contract

Before: `... | product_table | a | b`, where `a` and `b` are numeric,
range-checked nibbles.

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


The [shared product contracts](../../tests/u4_product_contract.rs) additionally
audit the existing numeric-only query in a full memory lifecycle, covering all
six positions in a three-pair hostile fixture, accepted aliases with exact
numeric meaning, caller state and the 2*n+259 resource frontier. Compiled range
mutations are executable using caller data below memory and caught by the same
typed rejection assertion. The new [exact quarter-square batch](u4-exact-product.md)
has a canonical input boundary and different output semantics; the research
canonical modulo comparisons add explicit byte checks to this existing query.
