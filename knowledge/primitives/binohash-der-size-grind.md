# Binohash exact DER-size nonce probe

A fixed legacy `SIGHASH_ALL` digest is signed repeatedly with deterministic
additional ECDSA nonce data until the DER encoding plus sighash byte is exactly
70 bytes. A policy-compiled 39-byte P2SH redeemScript checks `OP_SIZE 70`
before verifying the ECDSA signature. The signed transaction and controls are
funded and compared with pinned Bitcoin Core v30.3.

The search uses public seed `5a` repeated 32 times and counter-derived nonce
data. It finds the first exact-size signature after 188 trials. A 72-byte
signature that verifies the same digest fails the Script size check; a
corrupted 70-byte strict-DER signature passes the size check but fails ECDSA.
Core accepts the selected spend under consensus and default policy, and
rejects both controls. Evidence is `differentially-validated` and execution
is `policy-validated` for this fixture.

The P2SH scriptPubKey is 23 bytes, the redeemScript 39 bytes, and the complete
legacy spend 205 bytes / 820 WU, with a 111-byte scriptSig. It has zero witness
items and zero hint items. This is a single low-difficulty nonce search, not
the Binohash two-round protocol, pinning construction, or collision-security
proof. See the [research README](../../research/binohash-der-size-grind/README.md),
the [checked Core report](../../tests/data/binohash-der-size-grind-v30.3.json),
the [introspection comparison](../comparisons/introspection.md), and `OP-011`.
