# Weighted native Schnorr quorum

Can equal-weight keys share a native signature accumulator to reduce
script bytes and executed operations for a weighted Schnorr quorum?
Compare group counting and per-key multiplication with identical keys,
signer slots, public weights, threshold, and signed transaction shape.

## Construction

Each key has one dense witness slot. A nonempty valid Schnorr signature
contributes that key's positive public weight and an empty item
contributes zero. Each nonempty group is counted with
`OP_CHECKSIGADD`; its result is multiplied by the public group
weight and added to the total. All keys are checked before the final
threshold comparison. The generator rejects duplicate keys, zero
weights, empty groups and unattainable thresholds.

[BIP 342](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0342.mediawiki)
defines the native count and validation-budget behavior.
[BIP 340](https://github.com/bitcoin/bips/blob/2885f13d3f37890e328683166dbcbc60b488d13a/bip-0340.mediawiki)
specifies Schnorr verification. The [sparse threshold PR #310](https://github.com/solving-bitcoin/bitcoin-scripts/pull/310)
at revision `1fb1c6797596a784b2ce7dba6f4e4846015ffa03` compares an exact
unweighted threshold with routed witness indices. This experiment
keeps dense slots and asks whether the weight sum reaches a minimum.
The local baseline checks the same relation with `OP_CHECKSIG` and
one multiplication per key.

## Evidence and limits

At 64 keys the grouped and per-key leaves use 2,200 and 2,502 bytes,
executing 81 and 386 non-push operations. Both peak at 66 items and
charge 600 validation units for 12 nonempty signatures. Both data
witnesses serialize to 833 bytes from 64 ordinary items and no hints.
The complete witnesses are 3,070 and 3,372 bytes, including each
leaf and its 33-byte control block. Grouping is larger and executes
one more operation when each measured weight has one key.
See the [negative results](../negative-results/weighted-schnorr-quorum.md).

The [implementation README](../../src/signatures/quorum/README.md)
contains the measured fixtures and reproduction commands. Evidence is
`locally-reproduced`; deployment is `unclassified`. The local
transaction-aware interpreter uses the exact signed leaf and a checked
script-path commitment, with a synthetic outpoint. This does not
establish funded spending, relay policy, or a whole-output access policy.
