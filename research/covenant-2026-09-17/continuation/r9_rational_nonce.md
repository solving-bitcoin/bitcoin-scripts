# R9: rational nonce numerators and denominator reuse

Date: 2026-09-17. Question: can small public rational nonces `k=a/b mod n`
reduce the R8 interval search cost without charging an entire new set of
transaction hashes for each denominator? Comparison includes duplicate
nonces, curve generation, table construction, candidate scans and memory.

**Hashes can be reused, but the smaller interval numerators have an indexing
cost.** A fixed denominator is just R8 in a different scalar coordinate.
Several dyadic denominators reduce interval candidate counts; one can either
rebuild transformed tables or query preimages in the original table. Both
versions are implemented and return the same verified secp256k1 matches.
No output-binding improvement or sub-`2^64` total-work result follows.

## One denominator and exact duplicate removal

For public d and `r=x((a/b)G) mod n`, the signature equation is

```
b*z = sign*a*s - b*r*d mod n.
```

Use the R8 grid with `y=b*z mod n`, numerator a as its small multiplier, and
center `-b*r*d mod n`. With fixed b, y is a permutation of the scalar domain;
there is no reduction in the number of random digest queries. The small-a
interval geometry is identical to the original k=a geometry. Generating
`a*(G/b)` incrementally requires one point step per new numerator, plus the
initial public base-point calculation.

For the concrete portfolio choose `b_j=2^j`, j=0,...,D−1, and `a<=A`.
At j=0 keep every positive numerator. At j>0 keep only odd numerators.
Every excluded even numerator is already represented at a smaller denominator.
If

```
2*A*2^(D-1) < n,
```

two fractions are equal modulo n exactly when they are equal as rational
numbers: their cross-product difference has absolute value below n. No two
retained positive fractions are negatives modulo n either, because the
positive cross-product sum is below n. Thus this rule removes all scalar
duplicates and all ±nonce-point aliases within the stated finite cap.
The additional rare possibility `x(R')=x(R)+n` after reducing x modulo n is
not a scalar/± alias and is not claimed absent by that argument.

The exact number of distinct nonce classes and sum of interval multipliers are

```
R = A + (D-1)*ceil(A/2),
S_num = A*(A+1)/2 + (D-1)*ceil(A/2)^2.
```

For even A, `R=A*(D+1)/2` and `S_num=R*(R+1)/(D+1)`. A dense one-denominator
walk with R points instead has sum `R*(R+1)/2`. Under the same independent
type approximation used in R8, this is a factor `(D+1)/2` reduction in
interval candidate mass, rather than factor D: counting duplicate fractions
would overstate the improvement.

For example A=16 and D=4 gives 64 raw fractions but only 40 distinct nonce
classes. Their numerator sum is 328, versus 820 for 40 dense integer nonces.
The special supplied G/2 point occurs in this family. Its anomalously small
known r remains an independently available shortcut; uniform-r estimates
must not charge its rediscovery or treat it as typical random preprocessing.

## Two concrete ways to reuse the digest hashes

**Transformed tables.** Compute the original Q hashes once. Between dyadic
denominators update each stored scalar by `y <- 2*y mod n` and rebuild its
grid bucket. This costs exactly Q original hash evaluations, `(D-1)*Q`
modular doublings and `D*Q` insertions for full table rebuilds. The tables
can run sequentially: only Q digest records, their transaction-reconstruction
indices, bucket heads and a small point buffer need coexist. A found original
transaction is reconstructed from its index and rehashed for verification.

The usual linked-grid estimate remains about 56Q bytes before implementation
overhead; all D tables need not be resident. Clearing/rebuilding bucket heads,
memory writes and transformed-index computation are real work. In-place
reindexing can use a flat entry array and rebuild the linked buckets, rather
than retaining a second complete digest table.

**One original grid with preimage queries.** A transformed interval
`L<=b*z mod n<=U` can instead be queried through

```
ceil((L+t*n)/b) <= z <= floor((U+t*n)/b),  t=0,...,b-1,
```

clipped to `0<=z<n`. Empty intervals are skipped. After locating a candidate,
compute its transformed y and apply the exact R8 congruence with the correct
wrap residue. This needs one original table and no Q-element transform pass.
It trades those passes for up to b preimage intervals per transformed window.

For even A, the unweighted preimage branch sum across the canonical dyadic
portfolio is

```
H = A + (A/2)*(2+4+...+2^(D-1))
  = A*2^(D-1) = R*2^D/(D+1).
```

The candidate interval mass still depends on `S_num`, but bucket boundaries
now grow with H. For D=2 and D=3, H is respectively `4R/3` and `2R`, so this
is a legitimate alternative to rebuilding every table. It becomes costly
as D grows. A practical implementation could choose per denominator between
a transform/rebuild pass and preimage queries; `D*Q` is not an unconditional
indexing lower bound.

Both strategies require the finite interval premise `a*(B_s-A_s-1)<n` for
the supplied R8 API. For 55-byte items with retained r width at least 24,
`A<=2^64` suffices. The explicit fraction cap above is separate and also
checked. No unbounded denominator stream or geometric stopping-time argument
is substituted for these caps.

## Why a common denominator does not preserve the numerator saving

One can rewrite all dyadic fractions over the largest common denominator B,
using numerator `a*B/b`. Then one transformed grid suffices, but the interval
multipliers become those enlarged numerators. More generally R distinct
scalar classes up to sign, represented against one denominator, require R
distinct positive absolute representatives. Their sum is at least
`R*(R+1)/2`. Thus common-denominator folding cannot keep the reduced *unweighted*
numerator sum; this is a counting statement, not a weighted bound for every
possible r-dependent point-selection strategy.

For the A=16,D=4 example, folding to B=8 gives maximum numerator 128 and sum
1,536, even larger than the dense 40-point sum 820. Searching an implicit
multi-denominator index might share other data, but it must account for its
construction and queries. Neither fraction notation nor a common denominator
makes those operations disappear.

## Cost comparison and its limits

Let h be cost per original native hash, p per nonce point, i per grid insertion,
t per scalar-table transform, and c per reported interval candidate. For even
A and transformed tables the explicit full-batch counts give the proxy

```
C = h*Q + p*R + i*D*Q + t*(D-1)*Q
    + c*Q*F*R*(R+1)/(D+1),
```

where F is the retained-width pair-mass approximation, not a measured curve
distribution. Additional base computations, normalization, bucket lookups,
entry reads and audit must be charged separately. The point walk uses
`R-D` increment additions, `D-1` step doublings and up to `D-1` base-point
scalar multiplications, before affine-coordinate extraction. Denominator
inverses and reconstruction arithmetic also have costs. A full scalar
multiplication per nonce is unnecessary.

The saved cost table compares fixed expected incidence `R*Q*F=1`, optimizing
R/Q in this proxy. It does **not** compute expected work until a hit:
correlation across transformed copies and rare r types prevent replacing
`E[1/U]` with the reciprocal of mean pair mass. In the proxy, with
`alpha=h+i*D+t*(D-1)` and `beta=p+c/(D+1)`, the leading coefficient is
`2*sqrt(alpha*beta)/sqrt(F)`.

- With all five operation costs set to one, D=1 is best among D=1,...,8.
  D=2 costs 1.333 times its proxy; D=4 costs 1.789 times.
- In an intentionally different hypothetical regime h=64,p=i=t=c=1, D=5
  reduces the proxy by about 6.5%. This is a conditional constant-factor
  improvement, not a calibrated claim about native hashing or secp256k1.
- Raising p to 16 in that same regime makes D=1 best again.

For original-grid preimages the rebuild terms are replaced by one grid build,
on-demand transforms and bucket work scaling with H. That option can help
when rebuilds are more expensive than the additional branches; it is not
free query reuse. The experiment records both versions rather than declaring
one uniformly best. No actual large-memory implementation or hash-equivalent
benchmark was run, and no sub-`2^64` total honest work is established.

## Reproduction

Run `python3 research/covenant-2026-09-17/continuation/r9_rational_nonce.py`.
The [JSON](r9_rational_nonce.json) records four exact duplicate/folding cases
and a complete small secp256k1 comparison for A=16,D=4,Q=128.

The 40 distinct rational nonce points yield 39 retained rows for a 70-byte
signature test; the excluded point is the special smaller-r case. All four
transformed-grid match sets equal both their complete brute-force sets and
the original-grid preimage result. Three found signatures verify against the
original digests under public d=7. These are deterministic hash-label scalar
messages, not native funding/spending transactions or newly mined PoW.

The transformed strategy uses 128 original hashes, 384 modular table
doublings, 512 grid insertions, 144 bucket lookups, 135 entry reads and 59
congruence tests. The original-grid preimage strategy instead uses 128 grid
insertions, 318 bucket lookups, 314 entry reads and 59 on-demand transforms
and congruence tests. Both find the same three matches. These small actual
counts do not estimate the `2^63`-scale success distribution.

Evidence: `locally-reproduced`; deployment: `unclassified`. No Bitcoin locking
script or primitive is changed, no witness hints or consensus-validity claim
are introduced, and no field-library tests or metric updates are run.
The mandatory output reference and native enforcement under arbitrary
retained nonce choices remain unchanged open requirements.
