# R5: an actual hash-derived signature, including the r+n recovery branch

Date: 2026-09-17. Question: does the proposed proof-root signature really
bind outputs, and does comparing two native contexts repair its flag freedom?
The objective is exact amounts, scripts and output order with retained creator
state. These tests exercise the native ingredient; the blob is an existing
public preimage, **not a computation proof or a complete covenant**.

The ingredient executes successfully. Its unrestricted flag interpretation
does not bind outputs: identical witness data permit changing all of them.
A proposed context-inequality guard leaves this example intact.

## Public vector and native recovery

```
pi    = 00000000000000000200a8013bbb8678
alpha = SHA256(pi)
      = 301d020a7993dad81d0e10285a7e020f682a7033db72199360c2dc3599f2d302
flag  = 02  (SIGHASH_NONE)
r     = 574133785192103850564222
s     = 540859624094206118082341328620483283
```

For this particular r, x=r is not a secp256k1 point. The second possible
x-coordinate, x=r+n, is below the field modulus and has two valid lifts.
For either lift R and the actual transaction's NONE digest z, derive

```
P = r^-1 (s R - z G).
```

The ordinary verification equation holds. The three-byte redeem script
`a87cac`, `OP_SHA256 OP_SWAP OP_CHECKSIG`, consumes entry items `[P, pi]`.
It hashes pi and actually verifies the resulting alpha under P. This extends
the earlier DER-only parser check: a syntactically valid hash also supplies a
real successful signature here. No new rare event was searched for, and no
discrete logarithm of R or P was needed.

The same funded outpoint, same pi, and same P pass with a different recipient,
different output amount, two outputs instead of one, and reversed output
order. A second P obtained from the other sign of R also passes. Mutated pi,
a wrong P, and a missing pi all fail. These are witnesses showing the missing
flag condition, not claims about a complete QSB or Binohash protocol.

## Context inequality removes only a narrower case

The companion [flag analysis](r5_root_flags.md) proposes successful validation
before a separator followed by unsuccessful validation afterward. With the
same `[P, pi]` entry order, its full hash wrapper is

```
a87c6eadabac91
SHA256 SWAP 2DUP CHECKSIGVERIFY CODESEPARATOR CHECKSIG NOT
```

The first effective scriptCode is `a87c6eadac91`; the second is `ac91`.
An out-of-range SINGLE signature has the same constant digest in both
contexts and therefore cannot satisfy true followed by false. For NONE,
the two context digests differ but each still omits outputs. Recovering P
under the first digest produces a successful wrapper, unchanged when the
recipient is replaced. Core accepts both spends by consensus. Its documented
policy rejects the legacy CODESEPARATOR. This is a seven-byte variant of the
agent's eight-byte wrapper, saving its initial stack-order conversion.

## Reproduction, resources and evidence

Run `python3 research/covenant-2026-09-17/continuation/r5_root_core.py`.
[The JSON](r5_root_core.json) records complete funding/spending transactions,
recovered keys, both guard digests, Core provenance, and every policy and
consensus result. Funding is built in a fresh isolated local regtest chain,
with no wallet and no peer connections. Core 30.3 is pinned to commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`, and the archive and executable
hashes are checked by the existing helper. The model equations and transaction
serialization were compared with Core: evidence `differentially-validated`.

All eleven expectations pass: eight accepted transactions, three rejected.
The six ordinary positive vectors are `policy-validated`; the two guarded
positives are `consensus-validated`. The three malformed/incorrect vectors
are `consensus-incompatible`. The incomplete covenant proposal remains
`unclassified`.

| Successful boundary | Ordinary wrapper | Context-inequality wrapper |
| --- | ---: | ---: |
| P2SH locking script | 23 B | 23 B |
| Raw redeem script | 3 B | 7 B |
| scriptSig, including all pushes and redeem script | 55 B | 59 B |
| Entry data items in redeem script | 2 | 2 |
| Auxiliary hint items | 0 | 0 |
| Total scriptSig push items | 3 | 3 |
| Complete combined main/alt peak, by inspection | 4 | 4 |
| Executed non-push operations in redeem script | 3 | 7 |
| Additional P2SH operations | 2 | 2 |
| Serialized witness bytes | 0 | 0 |
| Complete one-output transaction weight | 548 WU | 564 WU |

The ordinary two-output transactions are 672 WU. Both operands coexist at
redeem entry. There is no hidden hint stream or repeated fragment; all
complete executions are far below the 1,000-item combined stack limit.
The bytecode is an explicitly raw consensus-boundary fixture, not an optimized
repository-generated primitive or library metric. No permissive local Script
executor, disabled consensus limits, field tests, or metric refresh was used.

For policy probes, the mempool is empty before each alternative. Disconnecting
an accepted block can otherwise re-add its transaction, causing replacement
fee errors to mask script policy. The local fixture restarts with mempool
persistence disabled, preserving the synthetic chain clock and height. Its
final JSON therefore records script-policy results rather than RBF conflicts.

Primary semantics: [pinned Core interpreter](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp).
The broader construction and cost questions remain in
[the root chronology analysis](r5_root_chronology.md).
