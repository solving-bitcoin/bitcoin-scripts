# Signed six-mode legacy sighash field-mutation matrix

- **Question:** Do the eight field-commitment boundaries in the host-only
  [matrix](../binohash-sighash-matrix/README.md) predict whether an unchanged
  ECDSA signature still authorizes a complete funded legacy spend?
- **Comparison objective:** Hold each signed two-input, two-output P2SH spend
  fixed except for one field, across `ALL`, `NONE`, `SINGLE`, and their
  `ANYONECANPAY` variants. Compare the local digest-change prediction with
  pinned Bitcoin Core v30.3 consensus and default relay-policy verdicts.
- **Evidence:** `differentially-validated`. The six baseline spends are
  `policy-validated` and mined under `consensus-validated` rules. Changed-digest
  variants are rejected by both Core block validation and relay policy.
  Unchanged-digest variants are accepted by `testmempoolaccept` but are not
  separately mined.

Each mode uses one selected P2SH `<pubkey> OP_CHECKSIG` input at index 1 and
one P2SH `OP_TRUE` input at index 0. The generator signs the selected input's
local legacy digest with public test key `[7;32]`, then copies that *same*
signature into all eight single-field mutations. Four confirmed 100,000-sat
funding outputs per mode provide both original and alternate prevouts, so a
prevout mutation tests the signature rather than a missing coin. Transaction
version is 2, baseline locktime 0, and the nonfinal input sequences have BIP68
explicitly disabled. The locktime mutation to height 1 remains final on the
funded chain; sequence mutations retain their disable bit. There is no RNG.

| Mutation | ALL | NONE | SINGLE | ACP&#124;ALL | ACP&#124;NONE | ACP&#124;SINGLE |
| --- | :---: | :---: | :---: | :---: | :---: | :---: |
| Version | reject | reject | reject | reject | reject | reject |
| Locktime | reject | reject | reject | reject | reject | reject |
| Selected prevout | reject | reject | reject | reject | reject | reject |
| Selected sequence | reject | reject | reject | reject | reject | reject |
| Other prevout | reject | reject | reject | accept | accept | accept |
| Other sequence | reject | accept | accept | accept | accept | accept |
| Selected output | reject | accept | reject | reject | accept | reject |
| Other output | reject | accept | accept | reject | accept | accept |

`ACP` means `ANYONECANPAY`. Every `reject` cell has a changed local digest,
Core policy rejection, and direct Core `generateblock` consensus rejection.
Every `accept` cell has an unchanged local digest and Core policy acceptance;
it has no separate block verdict. This gives 34 changed-digest rejections and
14 unchanged-digest policy acceptances. Six baseline spends are accepted by
default policy and confirmed together in a block. The checked report contains every
transaction, local digest, verdict, Core archive/binary hash, and node option.

## Reproduce

```sh
cargo test --locked --example binohash_signed_sighash_matrix
python3 tools/binohash_signed_sighash_matrix_regtest.py --download-core
python3 -m unittest discover -s tools -p 'test_binohash_signed_sighash_matrix_regtest.py'
```

The report is [tests/data/binohash-signed-sighash-matrix-v30.3.json](../../tests/data/binohash-signed-sighash-matrix-v30.3.json).
The tested P2SH locking scriptPubKey is 23 bytes and the selected redeemScript
is 35 bytes. Each complete legacy spend has two inputs, two outputs, zero
witness items, and **zero hint items**. Complete transaction weights are 1,152–1,156 WU; the other input
scriptSig is 2 bytes and the selected input scriptSig is 108–109 bytes. The
report records these values for every row. The separate funding
transaction is excluded from those spend costs. Combined stack peak and
executed opcode count are unmeasured.

This experiment isolates ordinary legacy signature-hash commitments. It calls
`binohash_digest` with no selected candidate signatures. The signed ECDSA
signature is supplied by `scriptSig`; it is not embedded in `scriptCode`, so
there is no selected `FindAndDelete` deletion, grinding, pinning puzzle,
Script-readable digest, or Binohash collision-security claim. The host matrix
remains the source for its selected dummy-push deletion experiment. The
out-of-range `SIGHASH_SINGLE` case is excluded here: both baseline outputs
exist, and its separate non-committing boundary is documented there.

Primary sources: [Binohash §2.4 and §3.1](https://robinlinus.com/binohash.pdf),
[Bitcoin Core v30.3 interpreter](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp),
and the [pinned release manifest](../../tools/bitcoin_core_release.json).
