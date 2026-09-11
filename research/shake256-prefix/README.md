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
- **Execution class:** strict local tapscript-context execution for the 32-byte
  prefix; deployment remains `unclassified`; the full output remains
  `research-unlimited` and consensus-incompatible.
- **Hard constraints:** input length `<512`, output length `1..=1024`, 520-byte
  item limit, and 1,000 combined main/alt-stack items.
- **Deterministic vector:** 32 message bytes of `0x42`, 32 output bytes.

## Reproduction

```sh
cargo test --locked hashes::shake256::tests::hashes_prefixes_to_the_standard_output --lib
cargo test --locked hashes::shake256::tests::small_prefix_stays_below_the_stack_limit --lib
cargo test --locked --test primitive_metrics shake256_prefix_metrics_are_current
cargo run --locked --example shake256_prefix_benchmark
```

## Result

The 32-byte prefix measures 2,000,127 generated script bytes, 65 serialized
witness bytes, 32 witness items, zero hints, and an 813-item strict peak. The
full 1,024-byte output remains 15,927,814 bytes and exceeds the combined stack
limit. Prefix correctness matches the independent reference across lengths
that include the 136-byte sponge-rate boundary.

The local tapscript opcode counter reports zero because it only counts legacy
execution; no executed-opcode total is inferred from static instructions.

## Falsification attempts

The focused tests cover empty and short reference behavior through the existing
1,024-byte vectors, prefix lengths below, at, and above one rate block, invalid
output lengths, and strict stack execution with output cleanup. Bitcoin Core
differential validation and relay-policy testing remain open.
