# SHAKE256 output-prefix experiment

- **Question:** Can a generation-time output prefix make the byte-lane SHAKE256
  construction stack-compatible for small outputs?
- **Hypothesis:** Prefixes that fit in the remaining stack headroom preserve the
  FIPS 202 output while avoiding the 1,024-item raw-output failure.
- **Comparison objective:** Compare the 32-byte prefix with the existing
  1,024-byte SHAKE256 construction under the `fragment-with-memory:` boundary.
- **Threat model:** Message byte items and output consumers are hostile; the
  primitive must preserve byte-lane semantics and callers must bind output
  length and any terminal digest predicate.
- **Execution class:** the reusable fragment remains `locally-reproduced` /
  `unclassified`; a separately scoped complete pinned Bitcoin Core v30.3
  consensus spend exists for the 32-byte prefix. The full output remains
  `research-unlimited` and consensus-incompatible; relay policy is unmeasured.
- **Hard constraints:** input length `<512`, output length `1..=1024`, 520-byte
  item limit, and 1,000 combined main/alt-stack items.
- **Deterministic vector:** 32 message bytes of `0x42`, 32 output bytes.

## Reproduction

```sh
cargo test --locked hashes::shake256::tests::hashes_prefixes_to_the_standard_output --lib
cargo test --locked hashes::shake256::tests::small_prefix_stays_below_the_stack_limit --lib
cargo test --locked --test primitive_metrics shake256_prefix_metrics_are_current
cargo run --locked --example shake256_prefix_benchmark
python3 tools/shake256_prefix_regtest.py --download-core \
  --output target/ci-reports/shake256-prefix.json
```

## Result

The 32-byte prefix measures 2,000,127 generated script bytes, 65 serialized
witness bytes, 32 witness items, zero hints, and an 813-item strict peak. The
full 1,024-byte output remains 15,927,814 bytes and exceeds the combined stack
limit. Prefix correctness matches the independent reference across lengths
that include the 136-byte sponge-rate boundary.

Executed-opcode count was not measured in this experiment and is not claimed. The
complete deterministic Taproot spend is accepted by pinned Core v30.3 via
`generateblock`; its terminal consumer discards the 32 hash outputs and checks
`OP_TRUE`, so this is complete-spend acceptance rather than independent hash
output validation. The 2 MB witness is a consensus result, not a relay-policy
or standardness claim.

## Falsification attempts

The focused tests cover empty and short reference behavior through the existing
1,024-byte vectors, prefix lengths below, at, and above one rate block, invalid
output lengths, strict stack execution with output cleanup, and the complete
Core consensus spend. Relay-policy testing and a smaller incremental
implementation remain open.
