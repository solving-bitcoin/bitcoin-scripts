# HORS-like HASH160 authentication

Authenticates a caller-selected subset of HASH160-committed preimages using
explicit witness indices.

- **Position:** exposes the subset-opening mechanism, not a complete signature
  scheme because message-to-index derivation is caller responsibility.
- **Evidence:** locally reproduced with boundary, ordering, and malformed
  witnesses.
- **Representative result:** `n=32,t=8` uses 809 script bytes and a 280-byte
  witness with 32-byte preimages; canonical indices `1..=8` are the 281-byte
  maximum and have a 50-item strict local stack peak. The exact-index variant
  uses 914 script bytes and the same 280/281-byte witness range, with a
  51-item peak; the representative executions count 88 and 164 non-push
  opcodes respectively.
- **Serialization boundary:** with `n=129,t=1`, canonical indices 127 and 128
  serialize to 36 and 37 witness bytes respectively; index 129 is upper-clamped to
  the final commitment by the existing verifier.
- **Index-binding boundary:** a strict local `n=32,t=8` test accepts raw index
  32 with the preimage for index 31. Default local minimal-data checking rejects
  noncanonical numeric encodings; disabling that check makes them alias their
  canonical numeric values. The clamped verifier itself does not bind raw index
  bytes. A separate exact-index API checks raw canonical encoding, range, and
  strictly increasing order in the script; its focused local tests reject the
  corresponding aliases with `MINIMALDATA` disabled.
- **Security:** strictly one-time; concrete forgery probability depends on
  parameters, index derivation, disclosures, and HASH160.
- **Research need:** specify and test a complete message-to-subset transform;
  the new exact-index fragment still needs a funded Core spend and integration
  with a legacy Binohash ECDSA consumer before protocol-level signature claims.
  A separate [local 2-of-3 toy](binohash-hors-subset-local.md) now reuses the
  same exact-HORS indices for pool-tag selection; funded legacy ECDSA
  integration remains open.

See the [implementation README](../../src/signatures/hors/README.md) and catalog
record `signature/hors-hash160`. The [negative result](../negative-results/index.md#nr-110-clamped-hors-openings-do-not-bind-raw-binohash-indices)
keeps the local execution and security implications separate.
