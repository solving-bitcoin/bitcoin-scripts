# bitcoin-scripts

Experimental Bitcoin Script arithmetic and cryptographic primitives.

## Layout

```text
src/
├── arithmetic/       # ScriptNum, u4, u31 fields, u32, bigint, and RNS
├── commitments/      # Integer hash-path and preimage-length commitments
├── hashes/           # RIPEMD-160, SHA-1, SHA-256, and BLAKE3
├── signatures/       # Lamport, HORS, and Winternitz OTS
├── ciphers/          # AES-128 and PRINCEv2
├── curves/           # BN254 fields, groups, and pairing
└── support/          # Script execution and shared pseudo-op helpers
```

Every primitive directory has a README covering parameters, measured script
and witness sizes, stack behavior, security assumptions, script-type
compatibility, standardness, and witness hints. Shared interpretation notes are
in [`docs/script-types.md`](docs/script-types.md) and
[`docs/standardness.md`](docs/standardness.md).

The cleaner domain paths are the canonical organization. Existing top-level
paths such as `u4`, `hash`, and `bn254` remain available as compatibility
re-exports.

## Metric snapshots

`tests/primitive_metrics.rs` computes documented script/witness sizes. Normal
tests fail if a snapshot is stale. After an intentional script change, update
the numeric README markers with:

```sh
UPDATE_PRIMITIVE_METRICS=1 cargo test --test primitive_metrics
```
