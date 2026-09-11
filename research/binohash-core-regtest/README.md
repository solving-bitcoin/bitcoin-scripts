# Binohash Core-regtest smoke fixture

- **Question:** Can the local environment reproduce a complete ordinary legacy
  P2SH `OP_CHECKMULTISIG` spend, the execution context required before a
  Binohash reproduction is attempted?
- **Hypothesis:** A disposable Core regtest can accept a deterministic 1-of-1
  legacy P2SH spend signed by a fixed test key, establishing the basic legacy
  transaction boundary without claiming Binohash extraction.
- **Comparison objective:** Separate ordinary Core legacy validation from the
  full Binohash protocol, which still needs signature grinding, mutation
  fixtures, digest extraction, and collision/work measurements.
- **Threat model:** The redeem script, signature, and transaction fields are
  treated as hostile by Core; the fixture uses a fixed test-only key and checks
  only completed signing and mempool acceptance.
- **Execution class:** Core regtest smoke evidence; not a cataloged Script
  primitive and not a deployment claim.
- **Hard constraints:** temporary regtest datadir, no persistent wallet state,
  legacy P2SH only, and no reuse of the test key for funds.

## Reproduction

```sh
research/binohash-core-regtest/run.sh
```

The local run used Bitcoin Core v30.2.0 and produced a 37-byte 1-of-1 redeem
script, `signed_transaction_complete=True`, and successful raw-transaction
acceptance. Pin an exact Core commit and add a Binohash-specific transaction
fixture before promoting this smoke result to differential evidence.

This fixture does not reproduce the paper's two-round grinding protocol, does
not expose a transaction digest to Script, and does not establish collision
resistance or honest-work bounds.
