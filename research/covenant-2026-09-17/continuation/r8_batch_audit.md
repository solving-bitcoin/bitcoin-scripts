# R8: independent audit of the interval/congruence join

Date: 2026-09-17. Question: does the R8 grid omit any valid small-nonce
signature because of modular wrap, an endpoint, a low-S sign, or its bucket
partition? This audit reads the implementation without modifying it. The
only writes are this report and its own Python/JSON artifacts.

**No omission was found for valid canonical inputs.** The original API did
silently omit noncanonical scalar inputs; the implementation now explicitly
rejects them and documents that callers reduce raw digests modulo the order.
All regression checks pass after that correction.

Evidence: `locally-reproduced`; deployment: `unclassified`. These are host
checks. No Script executor, Core process, transaction broadcast, field-library
test, new witness primitive or disabled consensus limit is involved. There
are no locking-script or hint-stack measurements for this off-chain audit.

## Reproducible coverage

- **18,258 exhaustive arc configurations**, comprising **307,922 individual
  membership comparisons**. For primes 5, 7, 11, 13, 17 and 19, enumerate all
  k from 1 through order−1, every canonical center, and all intervals with
  `1<=low<high<=(order+1)/2` and `k*(high−low−1)<order`. Directly enumerate
  `center ± k*s mod order` and compare the complete resulting set with the
  implementation's interval-plus-congruence condition. Negative, zero and
  positive wraps are recorded separately in JSON.
- **160 independent grid comparisons**. `random.Random(8171)` generates 20
  cases for each prime 5, 7, 11, 13, 17, 19, 31 and 101. Each digest list
  contains zero and order−1 plus random canonical values, including possible
  duplicates. Rows have random intervals, public r values and a common d.
  The reference enumerates every permitted s and both signs, then directly
  matches digest values. It does **not** call the implementation's
  `brute_join`, use modular inversion, or use any grid/arc logic. All full
  hit sets agree. Seed, generation order and per-case input hashes persist.

The sign calculation is exact: an arc has
`z + wrap*order = center + sign*k*s`. Its residue is therefore
`z mod k = (center−wrap*order) mod k`, and multiplying the signed quotient by
the recorded sign returns the positive low-S value. Python's floor division
for negative bounds is the required wrap convention. The bucket enumeration
includes both endpoint buckets, with exact interval and congruence filtering
after lookup. These are checks of this algorithm and its stated preconditions,
not a distributional or runtime proof for a large nonce portfolio.

## Original API counterexample and current regression

Use order=101, d=1, row `(k=1,r=1,low=2,high=3)` and raw digest 102. Its
canonical scalar is 1 and the correct hit is `(k=1,index=0,s=2)`. Before the
guard was added, the grid put 102 in bucket 1 while all canonical arcs were
in bucket 0, and returned no hit. The brute scalar calculation accepted it.
That original observed result is retained as historical evidence in JSON;
the audit does not reintroduce the old implementation.

The current API asserts a nonempty list whose every digest obeys
`0<=z<order`. The audit verifies rejection of `[]`, `[-1]`, `[101]` and
`[102]`, and verifies that `[102 % 101]` returns the expected hit. Assertions
are part of this research API; execute its tests with ordinary Python, without
the `-O` option that disables assertions. Existing secp256k1 fixtures and the
Core caller already reduce their raw hashes.

## Read-only check of the recorded Core artifact

The seven cases in [the root's Core results](r8_batch_core.json) were also
checked from their serialized transaction bytes. The audit independently
replaces the one input's scriptSig with the recorded redeem script, appends
ALL's four-byte suffix and hashes that serialization. All recorded sighashes,
txids and weights reproduce. It checks the 70-byte predicate and ECDSA
equation, and checks each successful k/sign pair by
`[s*sign*k]G = [z+r]G` under public d=1.

The resulting four positive and three negative classifications agree with
the stored Core consensus/policy outcomes. The valid wrong-length signature
is mathematically valid but fails the size predicate, as intended. This is
an independent host audit of recorded data; Core was **not rerun** by this
audit and it is not an independent consensus implementation. The underlying
Core experiment supplies its own execution evidence and resource metrics.

Reproduce with
`python3 research/covenant-2026-09-17/continuation/r8_batch_audit.py`.
The JSON records SHA256 fingerprints of the exact inspected implementation
and Core-result artifact. No complete covenant or sub-2^64 total-work claim
follows from the audit.
