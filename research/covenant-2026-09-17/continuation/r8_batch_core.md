# R8: interval-selected signatures against Bitcoin Core

Date: 2026-09-17. Question: does the new modular interval/congruence join
produce signatures for real native transaction digests that Bitcoin Core
accepts, including both low-S signs and the two ordinary r widths?

**All seven expectations passed:** four positive spends pass consensus and
default policy; three malformed or mismatched spends fail both. The positive
signatures come from actual transaction hashes found by the batch join,
rather than planted scalar digests. This validates a small-work 70-byte
boundary fixture. It does not mine a 55-byte signature, prove the large cost
model, bind a selected nonce in Script, or implement a covenant.

Evidence: `differentially-validated`; positive spends: `policy-validated`.
Bitcoin Core 30.3, immutable commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`; the runner verifies the pinned
official archive and isolated binary. Full provenance and every transaction
are retained in [the JSON](r8_batch_core.json).

## Actual search and native predicate

The public signing scalar is d=1, with public key G. The complete raw
redeem-script is

```
OP_SIZE <70> OP_EQUALVERIFY <compressed G> OP_CHECKSIG
```

The host enumerates the first 128 points kG using public point additions.
All 128 points happen to have r DER width 32 or 33. For a 70-byte signature,
r and s widths sum to 63. Each row therefore uses the exact admissible s
interval for width 31 or 30. These parameters satisfy the join's small-k
span condition. No exceptional G/2 point is used.

For each actual funded output and desired output list, 4,096 locktime
variants provide a table of genuine legacy ALL digests. Input sequences are
final, so the varying locktime does not create a maturity requirement. The
runner explicitly reduces each 256-bit digest modulo n before the join,
then retains the original digest for signature verification and reporting.
The join handles the positive and negative nonce branches, including wrap
residues, and returns the positive low-S scalar.

| Positive case | Known k | Nonce sign | r DER bytes | Locktime | Congruence tests | Naive pair tests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| First ordinary width | 1 | + | 32 | 864 | 69,898 | 524,288 |
| First ordinary width, negative | 1 | − | 32 | 228 | 70,482 | 524,288 |
| Leading-zero r width | 64 | + | 33 | 667 | 69,051 | 524,288 |
| Leading-zero r width, negative | 73 | − | 33 | 383 | 70,024 | 524,288 |

Each join makes 69,860 bucket lookups. The JSON separately records bucket
entry reads, congruence tests, wrapped windows and all distinct hits; these
are different operations and must not be conflated with total work. The
implementation computes the whole result set for reproducibility, without
stopping at its first hit. Every fixture succeeds in the first 4,096-digest
batch. These small counts demonstrate the actual filter, not a measured
linear scaling law at the large parameters.

## Funding, outputs and negative checks

An isolated temporary regtest node has no wallet or network peers. Its
funding transaction creates five identical P2SH outputs before any spending
digest search. The four positive spends use distinct funded outputs, so no
mempool conflict or replacement-fee rule can mask script validation. The
first three create one output each with different recipient scripts; the
fourth creates two ordered outputs of 490,000 and 500,000 satoshis. Each
spend pays 10,000 satoshis in fees.

The fifth funded output supplies three negatives:

- Reuse a valid 70-byte signature after changing the recipient: reject.
- Supply an empty signature: reject.
- Supply an independently valid 71-byte ALL signature under d=1: reject
  because its length is wrong.

The mempool is checked empty before each test. Each policy verdict is taken
before the corresponding direct `generateblock` consensus check. No block
invalidation or restart is needed. Passing different output lists on
different outpoints is not presented as a same-outpoint replay experiment;
the latter public signing ambiguity was established separately in R7's
host fixtures. The script itself has no reference to any intended output
list and does not enforce the honestly selected ALL flag.

## Complete boundary metrics

`complete-leaf:` 39 raw redeem-script bytes; one signature data item;
**zero auxiliary hint items**; combined main-plus-alt-stack peak **3** by
inspection; three executed non-push redeem-script opcodes. No altstack is
used. The P2SH wrapper contributes two additional opcodes in its separate
execution and has a 23-byte locking script in funding.

`complete-transaction:` each positive scriptSig is **111 bytes**, containing
the signature push and redeem-script push; all data are present at entry.
Serialized witness bytes are **0**. Each one-output positive transaction
weighs **772 WU**; the two-output transaction weighs **896 WU**. Funding
weight, offline digest tables and nonce setup are excluded from these spend
weights and are separately described above. No table is supplied on chain.

These are raw consensus-boundary vectors, not generated repository
primitives or optimized compiler metrics. No repository Script executor,
disabled consensus checks, field-library tests or metric refresh were used.

Reproduce with `python3 research/covenant-2026-09-17/continuation/r8_batch_core.py`.
The [exact join](r8_batch_incidence.md) and
[expected-cost audit](r8_portfolio_costs.md) state the remaining mathematical
and resource assumptions. Core acceptance of these small vectors does not
establish those assumptions or the missing output-reference construction.
