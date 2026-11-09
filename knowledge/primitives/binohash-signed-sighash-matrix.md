# Binohash signed legacy sighash field matrix

The [host-only six-mode matrix](../../research/binohash-sighash-matrix/README.md)
predicts which transaction fields affect a legacy digest. The
[signed Core fixture](../../research/binohash-signed-sighash-matrix/README.md)
checks those eight mutations across six canonical modes using complete funded
two-input, two-output P2SH transactions. It calls `binohash_digest` with no
selected candidate signatures, signs the resulting ordinary legacy digest,
and compares unchanged signatures against pinned Bitcoin Core v30.3 commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`.

Each of the six baselines passes default relay policy and is confirmed in a
Core block. All 48 single-field variants receive default-policy verdicts: 34 reject
and 14 accept. Where the local digest changes, Core rejects the signature under both policy
and direct block validation. Where the local digest remains the same, Core
accepts it under policy; those variants are not separately mined. This
supports `differentially-validated` evidence, with `policy-validated` baseline
spends and `consensus-validated` baseline and changed-digest block verdicts.
The exact accept/reject matrix is in the experiment README and
[checked report](../../tests/data/binohash-signed-sighash-matrix-v30.3.json).

The selected P2SH scriptPubKey is 23 bytes, its redeemScript is 35 bytes, and
each spend uses two inputs, two outputs, zero witness items, and **zero hint
items**. Complete transaction weights are 1,152–1,156 WU; the other
scriptSig is 2 bytes and the selected scriptSig is 108–109 bytes. The report
records each value for every mode and mutation. It excludes the separate funding
transaction. Combined stack peak and executed opcode count were not measured.

The signing signature is in `scriptSig`, absent from `scriptCode`; therefore
this fixture does not test embedded-signature `FindAndDelete`, signature
grinding, transaction pinning, or a Script-readable digest. Both outputs exist,
so it also excludes the out-of-range `SIGHASH_SINGLE` bug. The full Binohash
protocol remains [OP-011](../open-problems.md#op-011--reproduce-binohash).
