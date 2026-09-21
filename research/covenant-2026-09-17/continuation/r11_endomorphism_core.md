# R11: funded Core validation of public endomorphism signature pairs

Date: 2026-09-17. Question: does the digest-first endomorphism solver produce
actual accepted Bitcoin spends, with SINGLE and ALL on the same locked input?
The comparison uses one concrete funded P2SH outpoint and changes the output
recipient and amount while keeping the funding and locking script fixed.

**Three recomputed public witnesses pass consensus and relay-policy checks;
three malformed or mismatched cases fail.** The solver therefore supplies
a native free-signature pair after the transaction digest is known. It also
works for other recipients and amounts, so this is not an exact-output
covenant. Neither alpha nor beta is claimed to be a hash of a known preimage.

The [reproduction](r11_endomorphism_core.py) uses the 44-byte, 27-opcode raw
layout from [the endomorphism report](r11_endomorphism.md). Entry data are
`alpha, beta, P, Q`. Both canonical compressed keys must be distinct; alpha
and beta must each verify under both keys. The successful witnesses choose
alpha's flag 03 and beta's flag 01. The raw predicate does not itself decode
those flag bytes or enforce them for every possible witness.

## Transaction boundary and chronology

A fresh isolated regtest node mines 101 blocks to an OP_TRUE P2WSH output.
One mature 50 BTC coinbase funds a 1,000,000 sat P2SH output, a 1,000,000 sat
ordinary OP_TRUE P2WSH output, and 4,997,990,000 sat change. The funding fee is
10,000 sat. Its txid is recorded before any endomorphism pair is chosen.

Every tested spend has two inputs: the ordinary P2WSH input at index zero,
then the same P2SH outpoint at index one. There is one output, so alpha's
SINGLE digest is the legacy constant C=2^248. Beta's ALL digest commits the
actual output. The helper input supplies ordinary value and input position;
it performs no trusted reference computation. All six alternatives use
the same funding transaction and input outpoints.

The solver receives the actual `u=z_ALL/C`. It returns nonce coordinates
satisfying both modular relations and a known endomorphism multiplier t.
The test independently checks `t*R_alpha=R_beta`, computes both signatures
and shared keys, and then submits the full serialized transaction to Core.
All three positive vectors succeed at the first locktime candidate in this
particular deterministic fixture. This sample is not a worst-case or
expected-time guarantee for every digest.

## Results and complete costs

| Case | Core consensus | Standard policy | scriptSig bytes | Weight |
| --- | --- | --- | ---: | ---: |
| Recipient A, public witness | accepted | accepted | 227 | 1,406 WU |
| Recipient changed, old witness | rejected | rejected | 227 | 1,406 WU |
| Recipient B, recomputed public witness | accepted | accepted | 226 | 1,402 WU |
| Amount and recipient C, recomputed witness | accepted | accepted | 228 | 1,410 WU |
| Duplicate key | rejected | rejected | 227 | 1,406 WU |
| Alpha s changed from 1 to 2 | rejected | rejected | 227 | 1,406 WU |

Successful alpha/beta lengths are respectively 41/71, 40/71 and 41/72 bytes.
The first two positive spends pay 10,000 sat; the third pays 20,000 sat.
The scriptSig includes four witness-supplied data pushes and the redeemscript
push. The redeem boundary has **4 data items, 0 hint items, combined main-plus-
alt-stack peak 7**, and 27 executed non-push opcodes. The P2SH wrapper adds
2 executed non-push opcodes and a 23-byte locking script. The 44-byte redeem
script is a raw boundary vector, not a policy-compiled library primitive.

The locked input has no SegWit witness items. The ordinary input has one
witness item, the one-byte script 51. Complete transaction witness-vector
serialization is 4 bytes, plus 2 marker/flag bytes. Weight includes both:
`4*stripped_bytes+4+2`. These are complete two-input transaction metrics;
the ordinary input's cost is not omitted or called a hint.

Before each alternative, the mempool is empty. After a positive block test,
the block is invalidated and the isolated node restarted with mempool
persistence disabled and its clock preserved. This prevents a previous
alternative's mempool entry from causing an RBF rejection instead of a
Script-policy result.

## Evidence and reproduction

```
python3 research/covenant-2026-09-17/continuation/r11_endomorphism_core.py
```

The [JSON](r11_endomorphism_core.json) contains raw funding/spending
transactions, actual sighash preimages, the exact lattice solutions, public
keys, signatures, policy responses, block-test responses and binary hashes.
`actual_all_preimage` and `actual_all_digest` describe each test transaction;
the older unprefixed digest/trace fields explicitly describe the original
witness construction, which differs for the changed-output negative case.

Pinned Bitcoin Core: version 30.3, commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`;
archive SHA-256 `c42480fd26dd0b12c984e8063a1879165c94525c475162deb3ea2c3054dd5c2c`;
binary SHA-256 `fb6bbeb837fbaba84a0883602d718d749a4d739ee82ab326c3bc58094edddadb`.
No existing node, wallet, peer connection or real funds are used.

Evidence: `differentially-validated`; positive deployment `policy-validated`.
The deliberately invalid cases are `consensus-incompatible`. A separate
agent reconstructed all six transactions, txid/wtxid, witness weight, fees,
native digests and shared-key equations from the saved artifacts. The
duplicate-key case passes its four ECDSA equations but fails the distinct-key
guard; the other two negatives fail the expected signature checks.
No library code, field-library tests or primitive metrics changed.
