# Binohash reduced two-round subset composition

A single funded legacy P2SH redeemScript executes two consecutive one-of-two
embedded-signature selections and `OP_CHECKMULTISIGVERIFY` checks. Each
selected signature is removed from that round's legacy sighash scriptCode by
`FindAndDelete`, changing the corresponding puzzle digest. The selected
indices are `[0,1]` across the two pools. The first round checks one
candidate; the second checks two. This is a deliberately small executable
composition of the two-round mechanism reported in Binohash §5.2.

Pinned Bitcoin Core v30.3 mines the valid complete spend. Flipping either
selection without re-signing fails its `OP_CHECKMULTISIGVERIFY`; a valid but
wrong-size puzzle signature fails `OP_EQUALVERIFY`. The result is
`differentially-validated` and `consensus-validated` for this fixture. Default
relay policy rejects the valid spend under `CONST_SCRIPTCODE`.

The P2SH locking scriptPubKey is 23 bytes, the policy-compiled redeemScript
454 bytes, and the complete spend 744 bytes / 2,976 WU. There are zero
witness items and zero hint items. The two selectors are consumed, so the
fixture does not export authenticated indices to a later Script consumer.
It does not establish the paper's pinning work, full two-round grind,
collision resistance, or deployment. See the [research README](../../research/binohash-two-round-subsets/README.md),
the [Core report](../../tests/data/binohash-two-round-v30.3.json),
the [introspection comparison](../comparisons/introspection.md), and `OP-011`.
