# R8: expected work of a reusable nonce portfolio

Date: 2026-09-17. Question: does the mixed-width portfolio's sub-`2^64`
sample count remain below the budget when measuring expected work, rather
than the budget of a single trial with roughly one-half success probability?
This audit compares fixed-portfolio setup and subsequent digest search. It
grants free classification and does not supply a covenant or nonce binding.

The distinction is material. In the explicit large surrogate below, an
optimally sized fixed portfolio reaches approximately `2^63.94724` expected
input samples if generating a public curve point and obtaining a transaction
digest each cost one unit. Making point generation cost two digest-query
units raises this optimistic estimate to `2^64.45412`. These are conditional
model calculations, **not measured curve costs or universal lower bounds**.

Evidence: `locally-reproduced`; deployment: `unclassified`. This is a host
numerical experiment. There is no new Script fragment, witness, hint stack,
transaction, Bitcoin Core execution, or field-library test to measure.

## Expected queries must be conditioned on the actual portfolio

For a fixed set of R known nonces, let v_i be the uniform scalar-digest
probability of a 55-byte LOW_S signature using nonce i. R7 defines the exact
scalar-domain v_i for each r-width. Write

```
S = sum_i v_i,
U = measure of the union of their accepted digest sets.
```

Regardless of correlations between those acceptance sets, `U <= min(1,S)`.
With fresh independent uniform digests, conditional expected search is
`1/U >= 1/S`. If the nonce portfolio itself is sampled in an ideal width
model, averaging gives

```
E[queries] >= E[1/S] >= 1/E[S].
```

A rare, unusually short r can increase E[S] considerably while occurring in
few portfolios. Substituting `1/(R*F)` for E[1/S] can therefore understate the
work of the setup-and-search strategy. This does not invalidate R7's stated
pair-mass or one-trial probability calculations; it changes the objective.

The deterministic small experiment exhausts all 2, 4, 8 and 16 portfolio
type assignments for R=1 through 4. Each row has acceptance probability 1/16
or 1/64 with equal probability. It checks all three quantities exactly as
rational numbers. The last quantity uses an explicitly independent-cell
model, `U=1-product_i(1-v_i)`. No such independence is assumed for actual
secp256k1 modular intervals.

## A clearly scoped large approximation

The corresponding fixed-R width model is multinomial, with the ideal
uniform-r probabilities u_a from R7. For the numerical experiment only:

- Sparse width counts a<27 are approximated by independent Poisson
  variables with means `R*u_a`.
- Common-width contribution a>=27 is replaced by its mean B. Within the
  Poisson model this is optimistic by conditional Jensen; it is not an exact
  reduction of the curve distribution or of the original multinomial law.
- Widths below a_min are discarded. The values 24 and 25 correspond to the
  concrete small-multiplier interval algorithm investigated separately in
  [the batch-incidence report](r8_batch_incidence.md).

For `S_model=B+sum_a N_a*v_a`, the Laplace transform gives

```
E[1/S_model] = integral_0^infinity
  exp(-B*t + sum_a R*u_a*(exp(-v_a*t)-1)) dt.
```

The implementation substitutes `u=B*t`, integrates to u=48 with composite
Simpson quadrature, and optimizes `c*R + E[1/S_model]`. The discarded
normalized tail is at most exp(-48). Recomputing with four times as many
quadrature intervals changes the quoted results by less than `2e-8`
relatively; this is a convergence check, not a formal rounding-error proof.

| Smallest retained r width | Assumed point cost c | log2 R | log2 expected query estimate | log2 expected input-cost estimate |
| --- | ---: | ---: | ---: | ---: |
| 24 | 1 | 62.96586 | 62.92838 | 63.94724 |
| 24 | 2 | 62.47477 | 63.43317 | 64.45412 |
| 24 | 4 | 61.98316 | 63.93958 | 64.96153 |
| 24 | 16 | 60.99634 | 64.95604 | 65.97633 |
| 25 | 1 | 63.00565 | 63.00529 | 64.00547 |

Thus the unit-cost, free-classification case has only about 0.053 bits of
margin. An actual claim below `2^64` needs the operation unit, the complete
matching algorithm, curve generation and normalization, indexing and memory
traffic, setup verification, and a success/expected-work objective. This
audit does not establish any particular hardware ratio c, or preclude a
different strategy using the already supplied exceptional point G/2.

## Relation to streaming interval search

R8's concrete range/congruence join avoids examining every nonce/digest pair.
It may instead precompute Q digests and stream nonces until a match. That is
a different chronology from paying for R points first and then searching
digests. Its independent-row surrogate and stopping-time analysis belong
in the batch report; the results above must not be substituted for them.

Both models still need a treatment of actual shared-digest correlations and
finite small-k bounds. Restarting with the same scalar range reuses the same
public points, rather than independently resampling all width rows. Memory
is also explicit: Q stored 256-bit digests alone occupy `32*Q` bytes, before
indices or a hash-grid representation. At Q near `2^63`, this is near
`2^68` bytes. This is a resource requirement, not a measured runtime claim.

Even a fully accounted improved public signing algorithm would still need
to make the intended output list easier than another list under retained
creator state. Neither a portfolio nor OP_SIZE supplies that binding.

Reproduce with `python3 research/covenant-2026-09-17/continuation/r8_portfolio_costs.py`.
[JSON results](r8_portfolio_costs.json) include every cost case and the exact
small-model fractions. The input probabilities and special G/2 exception
are defined in [R7](r7_nonce_portfolio.md) and [R6](r6_length_puzzle.md).
