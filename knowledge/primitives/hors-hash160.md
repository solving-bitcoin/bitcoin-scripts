# HORS-like HASH160 authentication

Authenticates a caller-selected subset of HASH160-committed preimages using
explicit witness indices.

- **Position:** exposes the subset-opening mechanism, not a complete signature
  scheme because message-to-index derivation is caller responsibility.
- **Evidence:** locally reproduced with boundary, ordering, and malformed
  witnesses.
- **Representative result:** `n=32,t=8` uses 809 script bytes and a 280-byte
  witness with 32-byte preimages, exactly 16 data items, zero hints, and a
  strict combined stack peak of 50 items.
- **Security:** strictly one-time; concrete forgery probability depends on
  parameters, index derivation, disclosures, and HASH160.
- **Hostile indices:** the current verifier clamps indices above `n - 1`; it
  does not provide strict range rejection. A caller must bind the index domain.
- **Research need:** specify and test a complete message-to-subset transform
  before protocol-level signature claims.

See the [implementation README](../../src/signatures/hors/README.md) and catalog
record `signature/hors-hash160`.
