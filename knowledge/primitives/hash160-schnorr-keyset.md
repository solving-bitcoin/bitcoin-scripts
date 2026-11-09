# HASH160-committed x-only Schnorr signer set

Can a one-of-many native Schnorr leaf reduce its public key
constants by embedding HASH160 identifiers, while binding the
same revealed key to membership and signature validation?
Compare the exact signature predicate with raw embedded-key
membership and a witness index selecting an embedded key.
The hypothesis is that shorter constants offset the revealed
key witness at sufficiently large sets.

[BIP340](https://bips.dev/340/) defines the 32-byte x-only key.
[BIP342](https://bips.dev/342/#rules-for-signature-opcodes)
distinguishes 32-byte keys from unknown nonempty key types.
The verifier checks key length, derives the identifier, scans
the public list and checks the signature under that same key.
A separate [counterexample](../negative-results/hash160-schnorr-keyset.md)
shows how a committed short key passes a variant without the guard.

[PR #310](https://github.com/solving-bitcoin/bitcoin-scripts/pull/310)
sparsely schedules exact-threshold signature witnesses, and
[PR #323](https://github.com/solving-bitcoin/bitcoin-scripts/pull/323)
prices weighted quorum schedules over embedded keys. This
construction selects one signer using a hash identifier of the
revealed key and runs one native check.

The [comparison](../comparisons/hash160-schnorr-keyset.md)
prices data witness, the exact revealed leaf and control block,
combined stack peak, executed operations and signature budget.
See the [implementation README](../../src/signatures/hash_keyset/README.md)
for the signed synthetic transaction fixture.

At width 129, the HASH160 scan uses 3,243 complete witness
bytes and a six-item peak, versus 4,441 bytes and 131 items
for the indexed embedded keys. It executes 394 non-push
operations versus 73. Both charge 50.

Evidence is `locally-reproduced`. Execution is `unclassified`.
