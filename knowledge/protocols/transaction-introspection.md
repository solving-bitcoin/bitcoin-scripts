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

The repository now has a disposable [Core-regtest smoke fixture](../../research/binohash-core-regtest/README.md)
for an ordinary legacy P2SH `OP_CHECKMULTISIG` spend. It is only an execution
precondition: it does not implement Binohash, extract its digest, or reproduce
grinding. Do not model Binohash with the default tapscript executor: its legacy
signature context and transaction template are essential semantics. Full
reproduction still requires a pinned Core regtest, exact grinding parameters,
mutation constraints, and complete transaction costs. See `introspection/binohash`
and `OP-011`.
