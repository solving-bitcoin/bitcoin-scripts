# Bitcoin Scripts

Library of Bitcoin Script arithmetic and cryptographic primitives.

## State-of-the-art knowledge base

This repository is also an evidence-backed atlas for agents researching Bitcoin
Script primitives. Start at [`knowledge/index.md`](knowledge/index.md) to compare
constructions, execution assumptions, normalized costs, protocol dependencies,
negative results, primary sources, and open problems.

The machine-readable catalog can be queried without building the Rust crate:

```sh
python3 tools/kb.py list
python3 tools/kb.py search lookup
python3 tools/kb.py best hash/fixed script_bytes
python3 tools/kb.py validate
```

Catalog presence is evidence of coverage; catalog absence is not evidence that
a construction does not exist. Every result is dated and labeled as reported,
inspected, locally reproduced, or differentially validated.

## Layout

```text
src/
├── arithmetic/       # Integer backends, concrete fields, bigint, and RNS
├── commitments/      # Integer hash-path and preimage-length commitments
├── hashes/           # RIPEMD-160, SHA-1, SHA-256, SHAKE256, and BLAKE3
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

The domain-oriented hierarchy is the only public organization. Use paths such
as `arithmetic::u4`, `hashes::sha256`, `curves::bn254`, and
`support::execution`; flat aliases are intentionally not provided.

## Metric snapshots

`tests/primitive_metrics.rs` computes documented script/witness sizes. Normal
tests fail if a snapshot is stale. After an intentional script change, update
the numeric README markers with:

```sh
UPDATE_PRIMITIVE_METRICS=1 cargo test --test primitive_metrics
```
