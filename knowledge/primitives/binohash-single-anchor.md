# Binohash nine-byte SIGHASH_SINGLE anchor fixture

A strict-DER nine-byte ECDSA signature with `r = s = 1` and flag `0x03` is
embedded in a 45-byte legacy P2SH redeemScript. Its public key is recovered
for the historical out-of-range `SIGHASH_SINGLE` digest `01 00…00`. A funded
two-input, one-output spend places this anchor at input index 1. Pinned Bitcoin
Core v30.3 accepts it under consensus. Adding an output or moving the anchor
to input index 0 makes the output at the corresponding index exist; Core
rejects both unchanged-signature controls.

This is `differentially-validated` evidence and `consensus-validated` execution
for this one fixture. Default Core relay policy rejects the valid transaction
under `CONST_SCRIPTCODE`. The [implementation README](../../research/binohash-single-anchor/README.md)
specifies the exact signature, key recovery, funded transaction, controls,
cost boundary, and limitations; the [checked report](../../tests/data/binohash-single-anchor-v30.3.json)
stores the transactions and Core verdicts.

The P2SH scriptPubKey is 23 bytes, the redeemScript is 45 bytes, and the valid
complete transaction weighs 732 WU with no witness or hint items. Exact stack
peak and executed opcode count were not measured. The signature's fixed digest
means it commits to no transaction fields in the bug condition. This fixture
only validates an anchor primitive; it does not prove Binohash pinning,
grinding, collision security, or a Script-readable digest. `OP-011` remains
open.
