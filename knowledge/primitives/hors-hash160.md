# HORS-like HASH160 authentication

Authenticates a caller-selected subset of HASH160-committed preimages using
explicit witness indices.

- **Position:** exposes the subset-opening mechanism, not a complete signature
  scheme because message-to-index derivation is caller responsibility.
- **Evidence:** locally reproduced with boundary, ordering, and malformed
  witnesses.
- **Representative result:** `n=32,t=8` uses 833 script bytes and a 280-byte
  witness with 32-byte preimages.
- **Security:** strictly one-time; concrete forgery probability depends on
  parameters, index derivation, disclosures, and HASH160.
- **Research need:** specify and test a complete message-to-subset transform
  before protocol-level signature claims.

See the [implementation README](../../src/signatures/hors/README.md) and catalog
record `signature/hors-hash160`.
