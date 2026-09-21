# R8: an interval/congruence join for small public nonces

Date: 2026-09-17. Question: can the mixed-nonce search from R7 avoid testing
all R×Q nonce/digest pairs? In particular, can different congruences be
batched through CRT or polynomial evaluation with full bit and memory costs?

**Yes, this particular incidence problem has a concrete faster algorithm.**
For small positive nonce scalars k and short s, first locate digests in a
short interval and only then test their congruence modulo k. A hash grid
implements this with work proportional to its inputs and the candidates
reported by the intervals. It needs neither prime k nor a huge CRT integer.
Its large expected-cost accounting remains close to `2^64` even under very
optimistic assumptions, and it supplies no missing covenant reference check.

The R7 naive `R*Q` scan was an available implementation, not a lower bound;
this result fills that algorithmic gap in a restricted, explicit family.

## Exact arithmetic progression and wrap rules

Let the signing scalar d be public and fixed before funding. Generate
`k=1,2,...,R`, and let `r=x(kG) mod n`. For an exact low-S DER width b, let
`A<=s<B` be its positive integer range. A valid signature with nonce ±k obeys

```
z = c + sign*k*s mod n,  c = -r*d mod n,  sign in {+1,-1}.
```

Its two inclusive integer intervals before reducing modulo n are

```
[c+k*A,       c+k*(B-1)]
[c-k*(B-1),   c-k*A].
```

Assume `k*(B-A-1)<n`. Each interval crosses at most one modular boundary.
For each intersected quotient block `j*n .. (j+1)*n-1`, subtract `j*n` from
the clipped endpoints. Inside that modular window, require

```
z mod k = (c-j*n) mod k.
```

It is essential to include the `-j*n` term: the residue can change when an
interval wraps. The original positive s follows from
`s=sign*(z+j*n-c)/k`. The interval endpoints guarantee `A<=s<B`.
Both signs are required to cover the low-S normalization strategy.

For the 55-byte search `a+b=48`, keeping **r DER width a≥24** gives b≤24.
At `R<=2^64`, `k*B<=2^255<n`, so the premise holds. At `R≈2^63`, this
product is at most `2^254`. Discarded narrower-r rows are not silently counted
in the success rate: the retained ideal pair mass is approximately
`2^-125.840740`, corresponding to about 9.0039 ordinary width contributions,
not the 17 contributions from all widths in the previous LOW_S calculation.

These are achieved signing choices. The Bitcoin check still accepts other
nonce choices, and this algorithm does not establish deterministic nonce
enforcement or honest/forbidden-output asymmetry.

## The concrete join

1. Compute Q candidate native transaction digests and reduce them modulo n.
   Store each scalar and the index that reconstructs its transaction in a
   hash grid. Bucket width W is approximately n/Q; taking high scalar bits
   allows power-of-two buckets without long division.
2. Generate the known nonce points incrementally. Filter by retained r width,
   derive the s interval, and construct its two to four modular windows.
3. Visit the grid buckets intersecting each window. Check the exact interval
   for each entry, then its residue modulo k. Verify a found signature and
   the complete transaction before treating it as a result.

The implementation exposes
`grid_join(order, digests, rows, d) -> (hits, counts)`. Each row supplies
`k,r,low,high`; each hit is `(k,digest_index,positive_low_s)`. The input
digests must be a nonempty sequence of **canonical scalars `0<=z<order`**.
The API asserts this condition, and four tests reject empty or unreduced
inputs. A raw 256-bit hash must first be reduced; silently dropping hashes
at least n would be wrong.

The nonce walk can be streamed after the digest table is built. It does not
need an R-row nonce database. Batch affine normalization of curve points can
use a smaller additional buffer. The algorithm can stop at the first hit;
the included verification experiment deliberately scans the entire input
to compare every result with brute force.

## Work and memory: where the quadratic scan disappears

Put `Delta=B-A`. The total number of integer positions covered by a row's
two intervals, counting both signs before modular clipping, is

```
L_k = 2*(k*(Delta-1)+1)
    <= k*n*v_b,             v_b=2*Delta/n.
```

For fixed nonce rows and independent uniform scalar digests, the expected
number of interval candidates is exactly `Q*sum_k(L_k/n)`, apart from any
duplicated coverage counted twice. This bound requires no independence
between the nonce rows. A row visits at most `L_k/W+8` buckets; its expected
bucket-entry reads are at most `Q*L_k/n+8*Q*W/n`. Thus the grid has the
output-sensitive expected cost

```
O(Q + R + (Q/n)*sum_k L_k)
```

in bounded-width integer and expected hash-table operations, **plus R curve
point-generation steps** and all transaction hashing. It does not materialize
the full R×Q residue matrix. Deterministic correctness does not depend on
randomness; the estimate for the number of entries visited does.

In the separate ideal uniform-r approximation, `F=sum_a u_a*v_(48-a)` over
the retained widths. Since k is the walk index,

```
E[interval candidates] <= Q * F * R*(R+1)/2.
```

At an input size where `R*Q*F` is constant, this is O(R), rather than RQ.
This is the useful effect of small k. For arbitrary modular k near n, the
interval representation may cover the whole scalar domain many times and
does not give this bound.

Bit cost has not disappeared. Comparisons involve 256-bit digests; division
or remainder uses a 256-bit numerator and a k of at most 64 bits. Table
indices need approximately log2(Q) bits. In a variable-size bit model, each
reported candidate incurs the corresponding multiword comparison/remainder
cost, and each point step incurs `C_EC(256)` arithmetic work. In the fixed
256-bit model these are bounded constants, not free operations.

A concrete linked-bucket layout with Q digest records uses about `48Q` bytes
for 32-byte scalar, 8-byte transaction index and 8-byte next pointer, plus
about `8Q` bytes of bucket heads at one bucket per digest. Thus **roughly
56Q bytes** is a useful uncompressed memory estimate before allocation,
alignment, transaction-template state and normalization buffers. At
`Q=2^62.92`, this is approximately `2^68.73` bytes. A hash-map implementation
usually consumes more. The experiment uses ordinary Python containers; it
does not measure this enormous configuration or claim realistic deployment.

An incremental walk requires one group step per k, not one fresh scalar
multiplication, but obtaining each affine r still has a cost. For context,
the [Explicit-Formulas Database](https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html)
lists mixed Jacobian addition formulas costing 8 field multiplications and
3 squarings before affine extraction; batch normalization adds work.
This is an example accounting formula, not an assertion that this is the
fastest possible implementation or a calibrated hash-equivalent benchmark.

## Expected work, not a median sample count

The algorithm does not rescue a sample-only success estimate by declaring
everything else free. A fixed random portfolio has waiting time `1/U` given
its actual acceptance-set union U; averaging portfolios requires `E[1/U]`,
not the reciprocal of average pair mass. Sparse narrow-r types make this
distinction material. The independent
[fixed-portfolio cost audit](r8_portfolio_costs.py) computes a deliberately
optimistic Poisson/mean model and retains that distinction.

For comparison, this artifact also evaluates a different explicit surrogate:
hold Q digests and stream independent nonce rows until one hits. In that
surrogate the per-row success probability is

```
t(Q)=sum_a u_a*(1-(1-v_b)^Q),
E[T]=1/t(Q),
E[sum_{k=1}^T k]=1/t(Q)^2.
```

Actual rows share a digest table and have structured r(k), so this is not
a proven geometric law for the real algorithm. The surrogate also extends
the row stream without a hard k cap; the implemented two-to-four-window API
asserts its span premise. A capped walk needs failure/restart accounting,
or an explicitly implemented many-wrap fallback. Thus these values are not
unconditional expected runtimes of the supplied code. Its optimistic input-only
cost `Q+1/t(Q)` is minimized near `2^63.93696` for a≥24. At a≥25, it is
already approximately `2^64.00539`. Only a very small margin below `2^64`
exists in the first input-only estimate.

Charging one additional unit for every interval candidate, including the
whole final successful row, adds approximately `Q*F/t(Q)^2`; the minimum of
that accounting expression becomes `2^64.45395`. Stopping inside the final
row can reduce that charge, so it is **not a lower bound** on all
implementations. Bucket lookups, entry reads, EC arithmetic, hashing cost,
memory and audit would still have to be counted. No sub-`2^64` total-work
algorithm is established here.

## What CRT and polynomial trees do, and what they cost

For pairwise coprime moduli k_i, CRT can construct C satisfying
`C=c_i mod k_i`, with modulus `M=product_i k_i`. Then

```
F(C) mod k_i = F(c_i) mod k_i,
F(X)=product_j(X-z_j).
```

This identity is correct. If k_i is prime, a zero value means some digest
matches the congruence. Composite moduli do not permit that inference:
`2*3=0 mod 6`, although neither factor is zero modulo 6. Moreover the
congruence still needs its short-s range check; matching an arbitrary
residue does not imply that the resulting signature is short.

Known batch trial division uses one shared integer product and a remainder
tree to find relevant primes; see the authors' description of
[batch trial division](https://facthacks.cr.yp.to/batchtrial.html).
Here the row-dependent shifts are the extra obstacle. The straightforward
CRT reduction has `K=sum_i log2(k_i)` bits in M and C. Multiplying Q factors
`C-z_j` modulo M by standard sequential or modular-product methods costs
roughly `O(Q*Multiply(K))` bit work. With m moduli of about 64 bits and
m≈Q, that is near-quadratic in m, despite a K-bit final answer. An unreduced
product has up to QK bits. A full product tree can additionally retain
multiple levels of that data.

Expanding F over the integers is not a free alternative: with Q arbitrary
256-bit roots its coefficient height is O(256Q), and the expanded polynomial
can require Theta(256Q²) bits. The deterministic coefficient experiment
records 34,809 bits at degree 16, 135,205 at degree 32 and 532,991 at degree
64. Reducing coefficients modulo M caps each coefficient at K bits but
still permits QK bits of representation. Standard fast polynomial-operation
counts must be multiplied by their coefficient bit costs. These observations
describe these implementations; they do **not** prove that every possible
algebraic algorithm has quadratic complexity.

Prime-only nonce selection also has setup consequences. Walking all k up to
R yields only about R/log(R) prime candidates, under the usual asymptotic
prime-count estimate. Near `2^64` that is a factor of about 44 fewer rows;
skipping composite indices does not automatically skip the point-walk work.
Computing the selected prime points independently instead incurs scalar
multiplication costs. The interval/grid method has no primality condition,
uses composite k directly, and checks every reported congruence exactly.

## Reproduction and evidence

Run `python3 research/covenant-2026-09-17/continuation/r8_batch_incidence.py`.
The [JSON](r8_batch_incidence.json) records:

- 2,828 exhaustive small-domain membership checks, including 21 modular-wrap
  window cases, plus four rejected noncanonical/empty digest inputs.
- Nine deterministic radix-16 toy joins, each compared with every brute-force
  pair. For seed 1701 with 128 points and 256 digests, the grid makes 2,252
  bucket lookups, reads 2,228 entries and tests 1,949 congruences, finding
  exactly the same 25 matches as 32,768 naive pair tests. These quantities
  are deliberately separate; candidate tests alone are not total work.
- Eight planted secp256k1 scalar examples across 96 genuine known nonce points
  and 96 digests. The grid uses 192 bucket lookups, 210 entry reads and eight
  congruence tests, and all eight ECDSA equations verify. These digests were
  constructed algebraically; they are not native transaction hashes or
  newly mined PoW. The other candidate digests use deterministic SHA256
  labels; all are reduced modulo n.
- A small exact CRT identity check, the composite-zero counterexample,
  coefficient-size measurements and labeled surrogate-cost calculations.

An independent agent additionally checked 18,258 arc configurations over
small primes and 160 randomized grid/brute comparisons. Its API review
identified the unreduced-digest precondition, which is now asserted and
tested. This review did not execute a Bitcoin consensus interpreter.

Evidence: `locally-reproduced`; deployment: `unclassified`. This artifact
changes no Bitcoin primitive and adds no locking script, witness hints or
consensus-resource claim. It does not run the repository's tapscript executor,
field-library tests, or metric updates. Any complete Core boundary test
importing the join is a separate result and must state its own script,
transaction, witness, stack and deployment measurements.

The next concrete objective is an implementation-level total-cost comparison
using this exact interval join, and a native condition that remains sound
under every retained nonce choice. The known G/2 path still offers a much
cheaper 55-byte signature search. Neither that path nor this new join supplies
the mandatory comparison with the exact allowed output list.
