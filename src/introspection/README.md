# Legacy transaction introspection

This module contains host-side research helpers for transaction-dependent
legacy Script behavior. They are not tapscript fragments and must not be
executed with the repository's default tapscript-only assumptions.

## Binohash core

`binohash::find_and_delete` removes selected serialized signature pushes only
when they occur at Script opcode boundaries. `binohash::binohash_digest` then
passes the mutated `scriptCode` to rust-bitcoin's legacy sighash implementation.
This reproduces the deterministic mutation boundary used by a Binohash-style
subset grind; the proof-of-work search, signature construction, and complete
legacy transaction execution remain outside this helper.

The focused tests cover opcode-boundary deletion, subset-dependent digests,
the legacy `SIGHASH_SINGLE` bug constant, invalid selections, and invalid input
indices. Evidence is local host-side reproduction only; it is not consensus or
relay-policy validation.
