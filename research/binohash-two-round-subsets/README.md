# Two reduced Binohash subset rounds in one legacy spend

- **Question:** Can two separate embedded signature pools be selected and
  verified in sequence in one funded legacy Script, with each selection
  changing its round's puzzle sighash?
- **Comparison objective:** Check both selected rounds, flip either selector
  without re-signing, and use a valid but wrong-size puzzle signature in
  complete transactions under pinned Bitcoin Core v30.3.
- **Evidence:** `differentially-validated` for this reduced composition;
  execution is `consensus-validated`. Default relay policy rejects the valid
  spend under `CONST_SCRIPTCODE`.

## Construction and deterministic search

The selected input is index 1 of a two-input, one-output transaction. Each of
two rounds embeds a separate pair of public test ECDSA pool signatures. These
pool signatures use the out-of-range legacy `SIGHASH_SINGLE` digest and remain
valid with one output. Each round consumes a selector, chooses one embedded
signature, checks that its puzzle signature is exactly 71 bytes, and executes
`OP_CHECKMULTISIGVERIFY` with its puzzle and pool public keys. Legacy
`FindAndDelete` removes the selected embedded signature from that round's
sighash scriptCode. The two rounds use separate puzzle keys, pool keys, and
signature pairs. A final `OP_TRUE` supplies the terminal predicate, and the
valid script consumes both signatures and both selectors with an empty
altstack.

The fixed public keys and deterministic pool-signature nonce data define a
small search. The generator tries pool variants in increasing order and, for
each variant, tries selector 0 then 1 in each round. The funded fixture uses
variant 11 (12 variant attempts), selecting **index 0 in round 1 after one
candidate** and **index 1 in round 2 after two candidates**. The two selected
legacy puzzle digests differ. The funding harness varied a one-satoshi change
output adjustment over 92 deterministic funding templates to preserve the
same selected redeemScript while finding that outcome. These counts describe
fixture setup and its final two tiny pools; they are not a security-scale
grind or an estimate of the paper's work factor.

The Core result is [checked into the repository](../../tests/data/binohash-two-round-v30.3.json).
One complete spend passes block consensus. Flipping either round's selector
while keeping both puzzle signatures fails `OP_CHECKMULTISIGVERIFY` at input
1; a valid 72-byte signature for round 1 fails its `OP_EQUALVERIFY` size
check. Default mempool policy rejects the valid spend as `Signature is found
in scriptCode`. The report records all raw transactions, candidate digests
and sizes, selections, Core consensus/policy verdicts, and hash-verified Core
v30.3 provenance at revision
[`49faec4f87f5cd19c88db01a82e5c68b087c8227`](https://github.com/bitcoin/bitcoin/tree/49faec4f87f5cd19c88db01a82e5c68b087c8227).

## Costs and stack boundary

The policy-compiled P2SH redeemScript is **454 bytes**, below P2SH's 520-byte
push limit. Its complete locking scriptPubKey is 23 bytes. The complete
legacy spend is **744 stripped and total bytes, 2,976 WU, and 744 vbytes**.
Its easy and selected input scriptSigs are 2 and 605 bytes, respectively.
The latter contains two CHECKMULTISIG dummy items, two puzzle signatures, two
selector items, and the redeemScript. There are **zero witness items, zero
hint items, and zero serialized witness bytes**. The exact combined
main-plus-alt-stack peak and executed-opcode count were not instrumented.
The separate funding transaction is 158 stripped bytes, 163 total bytes,
637 WU, and 160 vbytes; it is excluded from the spend cost.

## Reproduce and limits

```sh
cargo test --locked --example binohash_two_round_subsets
python3 tools/binohash_two_round_regtest.py --download-core
python3 -m unittest discover -s tools -p 'test_binohash_two_round_regtest.py'
```

This fixture reduces each round to **one of two** embedded signatures and
uses a cheap 71-byte predicate. It does not include the paper's four pinning
puzzles, `n=120,t=8` pools, security-scale work, canonical multi-index
validation, or authenticated Script extraction of the concatenated indices.
The selectors are consumed by this script, so it does not itself export a
Script-readable Binohash. No collision-resistance or deployment claim follows
from this result. Default relay policy rejects it, so direct block inclusion
demonstrates consensus only. P2WSH and tapscript use different signature-hash
semantics and were not tested. The full protocol remains [OP-011](../../knowledge/open-problems.md#op-011--reproduce-binohash).

Primary sources: [Binohash §5.2](https://robinlinus.com/binohash.pdf) and
[Bitcoin Core's pinned legacy `SignatureHash`](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp).
