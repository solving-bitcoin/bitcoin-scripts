# Binohash 2-of-3 subset fixture

- **Question:** Can a legacy P2SH spend use canonical scriptSig indices to
  select two of three embedded signatures, vary `scriptCode` through
  `FindAndDelete`, enforce a signature-size condition, and pass the selected
  indices to a later Script predicate?
- **Comparison objective:** Compare a locally signed three-subset fixture with
  pinned Bitcoin Core v30.3 consensus and default relay-policy verdicts.
- **Execution class:** `differentially-validated`, `consensus-validated` for
  two selected funded spends; default relay policy rejects both.
- **Threat model:** The scriptSig is hostile. Duplicate, reversed,
  noncanonical, and out-of-range indices must not alias an accepted subset;
  an unrelated preimage or oversized puzzle signature must fail.

## Parameters

The generator fixes three distinct SIGHASH_SINGLE-bug pool signatures, selects
two in ascending order, sets a 71-byte maximum puzzle signature length, and
uses three public 16-byte preimages with distinct HASH160 commitments. It
requires a funding txid and destination script; the generator's optional
prevout indices default to 0 and 1. The runner funds two disjoint easy/P2SH
input pairs and deterministically searches the fee of their funding transaction
until `[0,1]` passes in the first spend, `[0,2]` passes in the second, and at
least one candidate fails the length filter. That search is **fixture setup**,
not the paper's transaction pinning or signature-grinding construction.

## Reproduction

```sh
cargo test --locked --example binohash_subset_fixtures
python3 tools/binohash_subset_regtest.py --download-core
python3 -m unittest discover -s tools -p 'test_binohash_subset_regtest.py'
```

The checked [Core report](../../tests/data/binohash-subset-v30.3.json) pins
Bitcoin Core v30.3 commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`
and archive/binary hashes. Two fresh-node runs of the report were byte
identical. In the first spend, `[0,1]` and `[0,2]` have 71-byte puzzle
signatures and `[1,2]` has 72 bytes. In the second, only `[0,2]` has 71 bytes.
The runner mines `[0,1]` and `[0,2]` in separate blocks with their respective
preimages, exercising two downstream commitments. In each spend, Core rejects
a changed pair with the original puzzle signature, reversed, duplicate, and
out-of-range indices, a noncanonical negative-zero index, a mismatched
preimage, and a different but valid 72-byte puzzle signature. Both valid
transactions are rejected by default mempool policy with `Signature is found
in scriptCode` (`CONST_SCRIPTCODE`).

## Script metrics

The P2SH locking scriptPubKey is 23 bytes; the raw redeemScript is 493 bytes
and is included in scriptSig. Each complete two-input, one-output valid spend
weighs 2,908 WU. Each has 2- and 588-byte scriptSigs. There is no
witness: **zero witness items and zero hint items**. The selected scriptSig has six data
pushes: CHECKMULTISIG dummy, puzzle signature, public preimage, two selectors,
and redeemScript. These values include the easy first input, selected P2SH
input, and complete transaction serialization; they exclude the funding
transaction and all full-protocol pinning/grinding costs. Combined main and
alt-stack peak and executed opcode count are not measured. This is a fixed toy
cost, not a Binohash parameter estimate.

## Stack contract and security

The redeemScript moves the preimage to altstack, checks each selector's raw
canonical value and ascending order, then uses two `OP_ROLL` selections over
three embedded signatures. `OP_CHECKMULTISIGVERIFY` checks the puzzle and
selected pool signatures. The two indices survive on altstack; their sum
selects one of three hardcoded HASH160 commitments for the supplied preimage.
This final equality is the terminal predicate and leaves one boolean result.
It proves that a downstream Script operation can consume the selected pair,
not that the pair is a collision-resistant transaction digest. The public
preimages and keys carry no secret or one-time-key guarantee.

The fixed pool signatures use the historical SIGHASH_SINGLE bug at input
index 1 with one output. The toy has no Stage 1 transaction pinning, no
two-round nonce extraction, no meaningful work factor, and no Lamport or
BitVM consumer. It cannot justify the paper's collision-security or economics
claims. P2WSH/tapscript lack these legacy `FindAndDelete` semantics; bare
legacy script is not exercised here. Default relay policy rejects the spend,
so miner inclusion on regtest is not a default-deployability result.

The raw bytecode intentionally bypasses the repository's generated-script
optimizer because exact embedded pushes are the test subject. This exception
is local to the consensus fixture.

## Knowledge-base integration

The catalog record is `introspection/binohash-subset-toy`. See the
[primitive page](../../knowledge/primitives/binohash-subset-toy.md),
[comparison](../../knowledge/comparisons/introspection.md), and
[OP-011](../../knowledge/open-problems.md#op-011--reproduce-binohash).
