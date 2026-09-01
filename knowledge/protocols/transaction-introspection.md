# Transaction introspection with Binohash

Binohash is an external reported construction whose primary source uses legacy
signature behavior and proof-of-work grinding to expose a collision-resistant
transaction digest to Script without a consensus change.

```text
Transaction mutations and legacy sighash
├── FindAndDelete / OP_CHECKMULTISIG behavior
├── subset and nonce grinding
├── two-round digest extraction
├── Script-readable digest
└── Lamport authentication into a later verification protocol
```

The current atlas has no local implementation. Do not model Binohash with the
default tapscript executor: its legacy signature context and transaction
template are essential semantics. Reproduction requires a pinned Bitcoin Core
regtest, exact grinding parameters, mutation constraints, and full transaction
costs. See `introspection/binohash` and `OP-011`.
