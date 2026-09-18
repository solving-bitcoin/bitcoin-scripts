# Signed radix-32 window decoder

## Question and hypothesis

Can ScriptNum's native sign representation make a reusable signed-window
decoder cheaper than five conditional bit-extraction branches per digit? The
hypothesis is that a shared staggered table wins locking-script bytes once a
batch amortizes its 156 table items, while remaining safe for hostile digits
and below the combined 1,000-item stack limit.

## Construction and objective

The fragment accepts canonical ScriptNums in `[-31,31]`, derives the sign with
`OP_LESSTHAN`, takes the absolute value, and uses one 156-item staggered table
to emit five magnitude bits. The comparison objective is locking-script bytes
for a batch of signed-window digits, with strict stack peak as a hard
constraint. Witness bytes, stack items, and byte-level opcode counts are
reported alongside the script size; there are zero auxiliary hints.

The like-for-like branch baseline performs the same canonical/range checks and
extracts each magnitude bit with conditional subtraction. It shares no table.

## Measured result

The `fragment-with-memory` 32-digit boundary includes table setup, checks,
queries, table cleanup, and output restoration/drop. It excludes input pushes,
witness serialization, terminal predicates, and unrelated protocol state.

| Configuration | Script bytes | Witness bytes | Complete items | Hint items | Peak items | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Shared table | <!-- metric:signed_window_table_batch32 -->1866<!-- /metric:signed_window_table_batch32 --> | <!-- metric:signed_window_table_batch32_witness -->65<!-- /metric:signed_window_table_batch32_witness --> | 32 | 0 | <!-- metric:signed_window_table_batch32_stack -->348<!-- /metric:signed_window_table_batch32_stack --> | <!-- metric:signed_window_table_batch32_opcodes -->1454<!-- /metric:signed_window_table_batch32_opcodes --> |
| Conditional branches | <!-- metric:signed_window_branch_batch32 -->2430<!-- /metric:signed_window_branch_batch32 --> | 65 | 32 | 0 | <!-- metric:signed_window_branch_batch32_stack -->194<!-- /metric:signed_window_branch_batch32_stack --> | <!-- metric:signed_window_branch_batch32_opcodes -->1758<!-- /metric:signed_window_branch_batch32_opcodes --> |

The table saves 564 locking-script bytes (23.2%) at 32 digits, at the cost of
154 additional peak stack items. A deterministic release sweep crosses over
between 8 and 16 digits: at 8 digits the table is 643 bytes versus 607 for
branches; at 16 it is 1,051 versus 1,215. At the no-preserved-state strict
limit, 140 table-decoded digits peak at 996 items. These are local measured
frontier points, not a global optimum claim.

The repository executor reports no useful dynamic opcode count for this
standalone tapscript fragment, so the table reports the reproducible serialized
non-push opcode count used by the existing metric harness. No validation-weight
or Bitcoin Core differential result is claimed.

## Security and execution class

Checked mode rejects non-minimal ScriptNum encodings, out-of-range values, and
indices that could escape the table. Unchecked mode is only safe after an
upstream canonical `[-31,31]` proof. The fragment does not bind a digit to a
scalar, point, message, or signature, and it provides no cryptographic
security claim. Local correctness is `locally-reproduced`; execution is
`unclassified` because the tests use the pinned tapscript interpreter without
Bitcoin Core consensus or relay-policy differential validation.

## Reproduction

```sh
cargo test --locked arithmetic::signed_window --lib
cargo test --locked --test primitive_metrics signed_window_metrics_are_current
cargo run --locked --release --example signed_window_benchmark
```

The benchmark uses 31 for every input digit, zero hints, and the repository's
centralized compilation policy. The signed-window decoder is a reusable
representation primitive, not a complete scalar multiplication or signature
verifier.

## Composed scalar reconstruction

The companion `signed_window_scalar_schedule` example composes the decoder with
a complete high-to-low U256 Horner consumer. The consumer performs five U256
doubles per digit, adds or subtracts the decoded magnitude, compares the exact
result, and leaves a clean `OP_TRUE` result. This is a
`complete-leaf:` context-free tapscript boundary including the digit witness,
consumer, output comparison, and terminal predicate; it excludes Taproot
commitment and transaction validation. There are no auxiliary hints.

| Digits | Shared table bytes | Branch bytes | Table delta | Table peak | Branch peak | Witness bytes/items |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 1,545 | 1,336 | +209 | 162 | 26 | 3 / 1 |
| 4 | 5,271 | 5,137 | +134 | 180 | 44 | 7 / 4 |
| 8 | 10,238 | 10,204 | +34 | 204 | 68 | 11 / 8 |
| 16 | 20,167 | 20,333 | -166 | 252 | 116 | 19 / 16 |
| 32 | 43,206 | 43,804 | -598 | 348 | 212 | 35 / 32 |

The table becomes smaller only at 16 digits and above. At 32 digits it saves
598 bytes (1.37%) while consuming 136 more combined main-plus-alt-stack items;
both schedules remain below the 1,000-item limit. The 32-digit scripts exceed
the 32 KiB optimizer cutoff and are therefore unoptimized under repository
policy. The result is `locally-reproduced` with deployment `unclassified`: it
validates scalar reconstruction, not elliptic-curve multiplication, signature
binding, or Bitcoin Core consensus/policy behavior.

Reproduce it with:

```sh
cargo run --locked --release --example signed_window_scalar_schedule
```
