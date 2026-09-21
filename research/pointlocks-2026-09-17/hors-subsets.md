# Fixed-size subsets of point locks

Question: can a HORS-like t-of-n subset improve point-lock proof publication
relative to one binary choice per bit? Yes at the encoding level. Concrete
transaction costs additionally depend on the shared-table verifier.

## Encoding

One pool contains n candidate tuples `(T_i,Q_i,h_i)`. Reveal exactly t distinct
candidates. A canonical increasing sequence of indices identifies one of
`binomial(n,t)` subsets. Rank/unrank that subset to encode/decode a digit.
This is a reversible encoding; it does not hash away the proof being published.

| Pool | Subsets | Bits per pool | Pools for 256 bytes | Candidate tuples | Revelations |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1-of-2 | 2 | 1 | 2,048 | 4,096 | 2,048 |
| 2-of-5 | 10 | 3.321928 | 617 | 3,085 | 1,234 |
| 2-of-6 | 15 | 3.906891 | 525 | 3,150 | 1,050 |
| 2-of-7 | 21 | 4.392317 | 467 | 3,269 | 934 |
| 3-of-7 | 35 | 5.129283 | 400 | 2,800 | 1,200 |

These are combinatorial counts, not measured script or transaction sizes.
Pool counts use the smallest integer k with `binomial(n,t)^k >= 2^2048`,
encoding the proof as a base-binomial integer. A decoder rejects integers
outside the 256-byte range. If using independently padded five-bit chunks
instead, 3-of-7 requires 410 pools, 2,870 candidates and 1,230 revelations.
Unused subset values must have an explicit rejection rule in that encoding.

The benefit is amortizing the candidate table over several revelations. For
fixed n, increasing t does not increase the bits per revealed scalar. Taking
t greater than n/2 is unnecessary for this objective: complementary subsets
carry the same information with fewer revelations.

## Verification obligations

- Enforce exactly t distinct indices, for example `0 <= i_0 < ... < i_(t-1) < n`.
- Authenticate the complete target/companion/signature-commitment association
  at each selected index. Range checks must reject rather than clamp indices.
- Perform both ECDSA checks and the size guard for every selected signature.
- Candidate secrets must not have public relationships that let disclosure of
  one derive the others. The underlying point-lock security assumptions remain.
- A pool is used for one disclosure. Multiple disclosures expose a union from
  which further equal-size subsets may be assembled.

A count of t successful checks is insufficient if the same candidate can be
counted repeatedly. The existing 1-of-7 redeem script's 482-byte measurement
cannot be reused as a 3-of-7 measurement: repeated verification, index checks
and cleanup have costs and must satisfy the P2SH and legacy resource limits.

## Relation to HORS

Section 2 of [Reyzin and Reyzin, Better than BiBa](https://eprint.iacr.org/2002/014.pdf)
(April 30, 2002; algorithm clarification October 17, 2007) describes an
injective message-to-fixed-size-subset construction generalizing Bos–Chaum.
Section 3 introduces HORS's hash-to-subset replacement. For publishing proof
bytes, the former mapping is the relevant one: HORS by itself authenticates a
separately supplied message and does not recover that message from its subset.
A tiny hash-to-subset range must not be mistaken for a large cryptographic
security parameter. With injective encoding, a different equal-size subset
requires at least one previously undisclosed independent secret.

The repository's older `src/signatures/hors/` helper checks caller-supplied
hash openings; it is not a ready-made implementation of this distinct-index
ECDSA subset construction.

## Shared-table prototype

The [subset probe](../../examples/pointlock_subset_probe.rs) now implements a
shared table of `HASH160(T_i), HASH160(Q_i), h_i` and a verifier repeated t
times. It enforces strictly increasing in-range indices, authenticates each
complete tuple, runs both signature checks and cleans up the table.

| Pool | Redeem script | Subsets tested | Maximum scriptSig | Combined stack peak |
| --- | ---: | ---: | ---: | ---: |
| 2-of-4 | 377 bytes | 6 | 640 bytes | 23 |
| 2-of-5 | 449 bytes | 10 | 712 bytes | 26 |
| 2-of-6 | 514 bytes | 15 | 777 bytes | 29 |
| 3-of-5 | 511 bytes | 10 | 904 bytes | 30 |

Each invocation uses t signature data items, 2t public-key opening items,
and t mandatory index hint items: 4t items all present at entry. P2SH adds one
redeem-script push. Legacy witnesses are empty; the scriptSig column includes
minimal data/index pushes and the redeem-script push, excluding its enclosing
transaction CompactSize prefix. The shared table and altstack temporaries are
included in the measured combined peak. These cases stay below 1,000 stack
items; no multi-pool stack composition is measured.

The 2-of-6 script has 106 static non-push opcodes and four signature checks.
Every valid subset passed the default-options legacy interpreter, and negative
checks rejected repeated/descending/out-of-range indices and mismatched
signatures, targets and companions. Scripts are compiled through repository
policy, with deterministic scalar seeds `[7;32]` through `[7+n-1;32]`.
The shared tapscript helper is not used. Larger 2-of-7 (578 bytes) and 3-of-7
(640 bytes) layouts exceed P2SH's element limit and are sizing-only.

Evidence: `locally-reproduced` for these compiled sizes and predicate executions;
`inspected` for the cryptographic composition. Deployment of fitting cases is
`unclassified`, pending Core and full-transaction validation. Combinatorial
counts use exact integer binomial coefficients. No complete BitVM3 protocol
or transaction-size claim follows from these counts.

```sh
cargo run --locked --example pointlock_subset_probe
```


## CHECKMULTISIG comparison

The [multisig experiment](multisig-probe.md) found no byte reduction from
replacing the paired checks with exact-list CHECKMULTISIG. Reordering each
selected unlocking record from `(sigma,T,Q,index)` to `(T,Q,sigma,index)` does
reduce the 2-of-6 CHECKSIG script from 514 to **512 bytes**, and its scriptSig
from 777 to **775 bytes**. The best measured CHECKMULTISIG counterpart takes
516 and 779 bytes. The candidate commitments still occupy 378 script bytes.
Two independent t-of-n multisigs over the full target and companion lists
are not equivalent: a Core-accepted cross-pair counterexample is recorded in
[the negative result](../../knowledge/negative-results/two-check-point-lock-extraction.md#two-full-pool-checkmultisig-calls-do-not-preserve-pair-binding).
