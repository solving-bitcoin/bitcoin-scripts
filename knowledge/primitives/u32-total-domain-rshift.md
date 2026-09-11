# Total-domain compressed u32 logical right shift

## Question and hypothesis

Can the repository's one-item compressed u32 wire support a total-domain
logical right shift without losing the `0x80000000` semantic word to ScriptNum
negative-zero behavior? The hypothesis is that a canonical raw-wire check plus
the existing byte rotation/AND machinery can close that correctness gap while
reducing witness item count from four bytes to one.

## Construction and objective

`u32_compressed_rshift(shift)` accepts the exact compressed representation
produced by `u32_compress`, for `1..=31`, and returns the compressed encoding of
`value >> shift`. It accepts the unique five-byte encoding of `-2^31` as the
wire for `0x80000000`; all other five-byte values, non-minimal aliases,
negative zero, and wrong-width items are rejected. The operation expands to
four bytes, rotates right, masks the high bits with the existing shared byte
logic table, and recompresses.

The comparison objective is witness width under equal strict local tapscript
execution. The closest baseline is the same rotate/mask operation over four
byte-valued witness items. Locking-script bytes, complete witness bytes,
coexisting data items, combined stack peak, and static non-push opcodes are
reported at a common fragment boundary. There are zero auxiliary hints.

## Measured result

The representative boundary uses shift 7 and semantic value `0xa5c319e7`.
It includes canonical input validation, table setup and cleanup, rotation,
masking, output compression or byte restoration, output dropping, and a
terminal `OP_TRUE`; witness input pushes and transaction framing are excluded.

| Configuration | Locking script | Witness | Complete items | Peak stack | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Compressed one-item wire | <!-- metric:u32_rshift_compressed_7 -->1143<!-- /metric:u32_rshift_compressed_7 --> bytes | <!-- metric:u32_rshift_compressed_7_witness -->6<!-- /metric:u32_rshift_compressed_7_witness --> bytes | 1 | <!-- metric:u32_rshift_compressed_7_stack -->272<!-- /metric:u32_rshift_compressed_7_stack --> | <!-- metric:u32_rshift_compressed_7_static_opcodes -->863<!-- /metric:u32_rshift_compressed_7_static_opcodes --> |
| Four-byte u32 baseline | <!-- metric:u32_rshift_bytes_7 -->637<!-- /metric:u32_rshift_bytes_7 --> bytes | <!-- metric:u32_rshift_bytes_7_witness -->12<!-- /metric:u32_rshift_bytes_7_witness --> bytes | 4 | <!-- metric:u32_rshift_bytes_7_stack -->272<!-- /metric:u32_rshift_bytes_7_stack --> | <!-- metric:u32_rshift_bytes_7_static_opcodes -->473<!-- /metric:u32_rshift_bytes_7_static_opcodes --> |

The compressed wire saves 6 serialized witness bytes and three entry items,
but adds 506 locking-script bytes and 390 static non-push opcodes. A
deterministic sweep confirms the same direction at shifts 1, 3, 7, 8, 15,
16, 23, 24, and 31. This is therefore a useful total-domain and witness-width
primitive, not a locking-script-size improvement.

The local executor reports zero dynamic opcode counts for this standalone
fragment, so dynamic execution counts and validation weight are recorded as
unknown rather than zero. Static counts are a separate reproducible metric.

## Correctness and threat model

The input is hostile witness data. The checked wrapper enforces canonical raw
ScriptNum encoding, recognizes only the canonical five-byte `-2^31` sentinel,
and rejects negative zero, non-minimal aliases, and wrong-width values before
using `u32_uncompress`. Deterministic tests cover every shift `1..=31` for
`0`, `0x7fffffff`, `0x80000000`, and `0xffffffff`, cross-byte mixed values,
non-minimal values, negative zero, invalid five-byte values, and six-byte
inputs.

This is local correctness evidence only. Tests use the pinned
`bitcoin-scriptexec` tapscript helper with the strict local stack limit. No
Bitcoin Core differential validation, relay-policy validation, complete leaf,
or cryptographic security claim is made; the execution class is
`unclassified` and the evidence level is `locally-reproduced`.

## Provenance

The ScriptNum/u32 representation and the negative-zero edge were checked
against the immutable `coins/bitcoin-scripts` source snapshot
`8f442e4bf8a744dd9bf69b2937bdebcaed5cae77`, registered as
`coins-bitcoin-scripts-8f442e4b`. Local execution uses the immutable
`bitcoin-script` and `bitcoin-scriptexec` revisions registered in
`knowledge/references/sources.json`.

## Reproduction

```sh
cargo test --locked arithmetic::u32::rshift --lib
cargo test --locked --test primitive_metrics total_domain_rshift_metrics_are_current
cargo run --locked --release --example u32_total_domain_rshift_benchmark
```

The open-problem target remains OP-014: close the Core differential and
complete-transaction boundary before calling this deployable.
