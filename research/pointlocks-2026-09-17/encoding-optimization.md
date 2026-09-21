# Encoding and transaction costs for point-lock publication

Question: minimize the complete creation-and-publication transaction bytes for
an arbitrary 256-byte value, using independent selectable point locks. Counts
of locks or signature checks alone are not the optimization objective.

[Executable calculation and serializer](encoding-optimization.py) uses exact
integer combinatorial capacities, deterministic rank/unrank tests, and full
transaction framing. Its placeholder sizing calculations are
`locally-reproduced`, with deployment `unclassified`. Separately, the complete
fixed-cardinality publication in [publication_core_check.json](publication_core_check.json)
is `differentially-validated` and `policy-validated`: it uses actual signed
transactions accepted and mined by Bitcoin Core. Each construction's execution
report defines its own evidence boundary. No ZKP is part of these encodings.

## Transaction boundary

The creation transaction spends one P2TR key-path input with a 64-byte signature.
It creates a P2TR helper output first, followed by one 23-byte P2SH output for
every pool. The assertion spends the helper first and all pool outputs, and
creates exactly one P2TR output. Thus every legacy input index is at least the
output count, as required by the constant SINGLE digest. No change or additional
authorization/refund outputs are included. All point-lock signatures in the
committed construction comparisons are 60 bytes including their sighash byte.

Every P2SH output costs **32 bytes to create**. Every corresponding input costs
`40 + CompactSize(scriptSig length) + scriptSig length` stripped bytes, plus one
byte for its empty witness vector when the transaction contains the P2TR helper.
The point-lock signatures, public keys, selectors and redeem script are all
legacy data and receive no witness discount. P2TR key-path witness data and
marker/flag total 68 bytes per transaction, plus those empty vectors. Input and
output count CompactSizes and rounding each transaction's weight separately
are included. The serializer reproduces the earlier 187-fixed-point example's
1,327 + 31,975 = 33,302 vB; that example does not encode 256 selectable bytes.

A single assertion exceeding 400,000 weight units is reported as such. The
chunked alternative consumes the helper first in each assertion and passes a
new first P2TR output to the next assertion. Each chunk has exactly one output;
all point-lock inputs therefore keep the required index condition. The creation
transaction still creates only one helper. The calculator checks each chunk's
weight and static sigop cost; this does not establish complete relay acceptance
or validate a package of unconfirmed transactions.

## Common-key sum locks: current fixed-cardinality result

The [common-key algebra](common-key-multisig.md) removes the per-candidate
signature commitment and makes the second verification key common to all
candidates. The holder generates the points and their opening signatures
jointly; this is a change to setup, not a drop-in lock for an arbitrary existing
point. Public signatures are 71 bytes in these deterministic fixtures, selected
by inexpensive nonce retries.

The best two-layout mixture among the measured fixed-cardinality P2SH
layouts uses **180 four-of-seventeen pools and three three-of-eighteen pools**.
There are **183 P2SH outputs, 3,114 independent candidate points, and exactly
729 revelations**. The reversible mixed-radix capacity is
`binomial(17,4)^180 * binomial(18,3)^3`, or 2048.0315305010695 bits. Every
pool's disclosure count is enforced by its own locking script.

| Construction | Creation | One oversized assertion | Two-TX total | Creation + two assertions |
|---|---:|---:|---:|---:|
| Common-key direct embedded-key CMS: 244 four-of-eleven + one three-of-ten | 7,951 | 192,628 | 200,579 | 200,690 vB |
| Common-key HASH160 key table: 180 four-of-seventeen + three three-of-eighteen | 5,967 | 179,353 | 185,320 | **185,432 vB maximum** |
| Same HASH160 layout, deterministic 256-byte publication fixture | 5,967 | 179,067 | 185,034 | **185,146 vB actual** |

Allowing nonstandard bare outputs gives a separate
[Core-validated 79-pool seven-of-48 publication](bare-publication.md): funding
98,308 vB and spending 63,074 vB, **161,382 vB combined**, with **161,560 vB**
canonical maximum. Its positive fixtures are `consensus-validated`, with default
policy rejection; the P2SH fixtures above are `policy-validated`. Every bare
output is created and consumed; independent recovery checks all 553 scalar
openings and the 256-byte message. Accepted partial publication and surplus
codewords remain explicit application boundaries.

The HASH160 table row authenticates the selected verification keys using a
20-byte commitment. It therefore adds a key-hash binding assumption. Under
malicious candidate setup, a collision between two valid generated keys can
substitute a different intended point; generic collision work is about 2^80,
not a claim of preimage-only or 128-bit binding. The direct embedded-key CMS
row avoids this additional inner key-hash commitment. Both use ordinary P2SH
funding outputs. These are distinct assumption sets, not interchangeable rows.

The fixed lookup pools use 505-byte and 502-byte redeem scripts. Every selection
has one signature, one public key and one lookup-depth hint; complete entry
counts are 12 or 9, with four or three hint items respectively. The redeem
script is an additional scriptSig push. All entry data coexist within their
own input; different P2SH inputs have separate stacks. Across the publication
there are 729 hints and 2,187 complete entry data items, plus 183 redeem-script
pushes. The measured combined peaks are 33 and 31, respectively.

The maximum scriptSig lengths are 938 and 829 bytes. Depth hints at most 16 use
one-byte opcodes, while a few larger depths need two-byte pushes; the actual
fixture therefore saves 286 bytes against the maximum. It uses a seeded random
256-byte value and lexicographic subset ranking, with big-endian mixed-radix
folding in funding-output order. The direct CMS pools have zero selection hints,
one mandatory empty CHECKMULTISIG dummy, and four or three signatures; they
store their verification keys directly.

The two fixed lookup assertion chunks contain 101 and 82 pools. For the
recorded fixture they measure 396,257 WU / 99,065 vB and 320,454 WU / 80,114 vB.
The creation measures 23,868 WU / 5,967 vB. All outputs' creation and later
consumption, CompactSize fields, helper signatures, empty witness vectors and
per-transaction rounding are included.

See [the full-publication harness](publication_core_check.py),
[selection fixture](publication-selection.json), and
[Rust transaction builder](../../examples/pointlock_publication_probe.rs).
The setup grant from a mined test coinbase merely supplies the initial assumed
P2TR funding input and is excluded from these publication costs.

**End-to-end validation passed on Bitcoin Core 30.3**, immutable commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`. All three publication transactions
passed default `testmempoolaccept`, entered the mempool with `sendrawtransaction`,
and were mined in sequence. No wallets, peers or network activity were enabled.
An independent Python decoder read the actual Core-decoded scriptSigs, checked
every selected key against its funded hash table, extracted **all 729 scalars**,
verified `tG = P+G`, and recovered the original **256 bytes**. The recovered
value's SHA256 is `8848d099157eaf73291dc812ce48ba465183c68fa7aa6bac5172108253af9dd4`.
The report is [publication_core_check.json](publication_core_check.json), with
complete transactions in [publication-transactions.json](publication-transactions.json).
This validates one full canonical publication fixture, not a complete BitVM3
protocol or a universal parser for every consensus-valid noncanonical spend.

```sh
python3 research/pointlocks-2026-09-17/encoding-optimization.py --write-selection research/pointlocks-2026-09-17/publication-selection.json
python3 research/pointlocks-2026-09-17/publication_core_check.py
```

## Conditional CSV cardinality binding

Adding `<5-j> CHECKSEQUENCEVERIFY DROP` to each inactive branch produces a
**519-byte** variable one-through-five-of-fifteen redeem script. At a fixed,
authenticated input sequence `5-t`, removing a revelation then fails CSV.
This needs **unavoidable authorization binding every input sequence**: merely
including the conventional helper does not suffice, because the point-lock
script does not require that helper to be present. Raising the sequence restores
the deletion path. The scheme also requires transaction version 2 and up to
**four blocks of funding maturity**. It introduces no ZKP.

For the conditional 176-pool, globally 638-revelation encoding, 71-byte
signatures give `scriptSig = 537 + 104*t` bytes, or 641 through 1,057 bytes.
Every pool has 15 entry items including five depth/sentinel hints, a measured
combined stack peak of 34, 138 static non-push operations and ten static sigops.
Across 176 separate inputs there are 880 hints and 2,640 complete entry items;
these do not coexist in one Script stack. The redeem-script push is additional.

| Conditional CSV transaction | Weight | Virtual bytes |
|---|---:|---:|
| Creation: one helper + 176 P2SH outputs | 22,972 WU | 5,743 |
| One oversized assertion | 674,348 WU | 168,587 |
| Two-transaction total | separately rounded | **174,330** |
| Assertion chunk: 96 pools, 272 revelations in the sizing fixture | 336,412 WU | 84,103 |
| Assertion chunk: 80 pools, 366 revelations in the sizing fixture | 338,380 WU | 84,595 |
| Creation + both assertion chunks | 697,764 WU | **174,441** |

The chunks group the 96 pools with the fewest revelations first and the
remaining 80 second. This keeps both below 400,000 WU for every permitted
638-revelation profile; the input counts are multiples of four, so their
combined rounded size remains exactly 174,441 vB. Output creation and input
consumption are both included. These costs assume the required authorization
already exists with the stated transaction shape; they do not price an
additional mechanism that makes it unavoidable.

[CSV pool vectors](sum-csv-vectors.json) passed all 30 expected outcomes;
[the Core report](sum_csv_core_check.json) also includes one existing control,
for 31 successful expectation checks. **The 256-byte CSV publication has
not been built and validated end-to-end.** The 174,441-vB result is exact
serialization accounting under the stated conditional protocol assumptions,
with sizing evidence `locally-reproduced` and deployment `unclassified`.
The fully validated fixed-cardinality fixture remains the 185,146-vB result
above.

## Earlier committed fixed-size subset comparison

The basic mixed-radix codec treats the 256 bytes as an integer. A pool revealing
`t` of `n` independent candidates has radix `binomial(n,t)`. It uses the smallest
number of slots with product of radices at least `2^2048`. Unused encodings are
rejected. It never counts reveal order as additional information: the same set
of revealed secrets can be reordered without learning another secret.

| Construction | Redeem / max scriptSig | Pools | Candidates | Revelations | Two transactions | Creation + weight-bounded assertion chunks |
|---|---:|---:|---:|---:|---:|---:|
| Original 2-of-6 | 514 / 777 B | 525 | 3,150 | 1,050 | 447,658 vB | 448,103 vB; 5 chunks |
| Reordered 2-of-6 | 512 / 775 B | 525 | 3,150 | 1,050 | 446,608 vB | 447,052 vB; 5 chunks |
| Exact-list CHECKMULTISIG, reordered | 516 / 779 B | 525 | 3,150 | 1,050 | 448,708 vB | 449,153 vB; 5 chunks |
| Destructive depth lookup 2-of-6 | 474 / 738 B | 525 | 3,150 | 1,050 | 427,183 vB | 427,626 vB; 5 chunks |
| Same lookup, with final binary slot | mixed | 525 | 3,146 | 1,049 | 426,705 vB | 427,147 vB; 5 chunks |

The final row uses 524 radix-15 slots and one radix-2 slot:
`2 * 15^524 >= 2^2048`. It is the best result in the calculator's exhaustive
search over mixtures of at most two recorded fixed-size layouts, under their
recorded worst-case scriptSig lengths. It is not a lower bound over all scripts.
The lookup's 738-byte maximum includes the occasional two-byte depth push;
particular subsets can use 737 bytes. References: [original subsets](subset-probe.md),
[CHECKMULTISIG comparison](multisig-probe.md), and the lookup experiment.

## Conditional global constant-weight encoding: deletion-malleability limitation

A smaller arithmetic encoding is to choose the total number of revelations
across all pools, rather than fixing it separately in every pool. Each pool
still requires at least one independently protected point; no empty public
spending branch is added.

For the locally executed variable **1-through-3 of 5** layout, use **453 pools**
and require **exactly 862 distinct pool-indexed points in total**. The number of
possible publications is

```text
[x^862] (5x + 10x^2 + 10x^3)^453 >= 2^2048.
```

Its base-2 logarithm is 2048.230529414806. There are 2,265 candidate points.
The encoder ranks these complete selections and maps each 256-byte integer to
one rank. The decoder reconstructs the selected subsets from the transaction,
checks the global count, ranks them, and rejects ranks at least `2^2048`.
The script requires distinct selections within each pool. Pool identity comes
from the funded output; candidate secrets are independent between pools.

**This is not a sound drop-in replacement for fixed-cardinality publication.**
A third party can replace one optional opening with its empty sentinel, reducing
the global revelation count while all Bitcoin input scripts remain valid. The
P2TR helper's signature does not commit the other inputs' scriptSig bytes, so
it does not stop this mutation. Merely rejecting the resulting count in an
offchain decoder does not prevent a valid on-chain but undecodable publication
or its protocol consequences. An explicit mechanism for handling such malformed
publications would be needed before using this variant. The end-to-end fixture
above uses fixed per-pool cardinalities instead.

**Even conditionally, the global count is a mandatory protocol validation rule.** The P2SH scripts
check only their local one-through-three selections. Without the global rule,
removing a revealed point could change the decoded value using only secrets
already disclosed. With a fixed total, two different valid sets cannot contain
one another: an alternative codeword needs at least one new independent point.
This combinatorial argument is conditional on the point locks' own extraction
and binding assumptions; it does not close their ordinary-digest proof gap.
It is not a drop-in BitVM3 integration until its verifier enforces this codec.

The measured redeem script is **467 bytes**. Each input supplies three padded
records, all present at script entry. There are three depth/sentinel hint items,
and nine signature/key/dummy data items, for **12 unlocking items**; the P2SH
redeem-script push is additional. The maximum combined stack peak is 30. The
script contains six static signature operations, regardless of how many
selections are made. Across 453 separate inputs there are 1,359 selector/sentinel
hints and 5,436 complete entry items, including those hints; these do not coexist on one Script stack.

With `t` selected points, the scriptSig has `482 + 126*t` bytes: **608, 734 or
860 bytes**. Skipped records consist of four minimally pushed empty elements.
The fixed total of 862 revelations makes aggregate serialized size independent
of their distribution among pools:

| Transaction | Virtual bytes | Weight |
|---|---:|---:|
| Creation: one helper + 453 P2SH outputs | 14,609 | 58,436 WU |
| Single assertion: helper + all 453 pools | 346,664 | 1,386,653 WU |
| Both | **361,273** | separately rounded |

This is sizing only for the conditional variable-cardinality variant. The
single assertion exceeds the standard transaction weight bound. The
calculator constructs a four-assertion example with **361,604 vB** total,
including creation. Its individual assertion weights are 397,959, 398,396,
398,408 and 193,214 WU. This profile encodes the 256-byte integer `2^2048-1`;
chunk rounding and partitioning can vary slightly for other messages even
though the unchunked total is fixed. The table reflects exact serialization,
not a complete cryptographic or policy validation.

Variable one-through-four of five fits a 518-byte redeem script but is worse:
its best uniform configuration uses 432 pools and 891 revelations and costs
376,984 vB before splitting. Variable one-through-three of four costs
393,460 vB. Allowing more local choices is not automatically more efficient
when it expands every redeem script.

The search enumerates every pool count through 700 and every admissible global
revelation count, with exact coefficients. Coefficient dynamic programming also
provides rank/unrank. Deterministic round trips cover integers 0, 1, `2^2048-1`
and eight seeded random 256-byte integers. These are encoding and serialization
tests, not Bitcoin execution tests.

```sh
python3 research/pointlocks-2026-09-17/encoding-optimization.py
python3 research/pointlocks-2026-09-17/encoding-optimization.py --variable-script 467 --max-selected 3
```

## Limits on sharing and security tradeoffs

Reusing the same candidate secrets in independent digit pools does not provide
free compression: once their union is revealed, the secrets can be rearranged
into other pool selections. The global code above uses independently generated
points at every pool position, not repeated copies of a small secret table.

Shortening the old fixed-nonce signature by choosing a tiny `s` is also not a
free security-preserving optimization: the known nonce gives a public affine
relation between `s` and the locked scalar, enabling a bounded discrete-log
search. The comparisons retain the 60-byte baseline rather than silently
exchanging security for a few bytes.

For the restricted three-HASH160 explicit-table family, even an idealized
single unrestricted global pool is expensive. At least 2,054 independent
candidates are needed because `binomial(2053,floor(2053/2)) < 2^2048` while
2,054 suffice. Their three 21-byte hash pushes already cost 129,402 bytes.
Minimizing `63*n + 129*t` over `binomial(n,t) >= 2^2048` gives 236,817 bytes at
`n=2297,t=714`, before selectors, verification and transaction framing. This
is a restricted-family accounting bound, not a universal lower bound for
point locks, and does not apply to constructions that remove those commitments.
