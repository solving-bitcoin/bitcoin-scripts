# R21 independent audit: fixed-source hash-weight search

The scoped fixed-translation argument in
[r21_hash_weight_cost.py](r21_hash_weight_cost.py) is sound, with one explicit
query-accounting condition: both endpoint hashes of a claimed successful
edge must be counted. Equivalently, include the hash evaluations used to
check a returned candidate in the query total. An algorithm allowed to
return an unchecked guessed edge has a nonzero success probability even at
zero oracle queries, so the zero-query bound would not apply literally.
Allowing two additional queries covers one such final candidate.

The independent [audit](r21_hash_weight_audit.py) reads the saved
[construction data](r21_hash_weight_cost.json) but imports neither the
construction nor its adaptive dynamic program. The [audit results](r21_hash_weight_audit.json)
are `locally-reproduced` / `unclassified`; they make no native Script or
signing claim.

## Graph and adaptive-query bound

For one fixed source `(r,s)`, write

```
P(z) = (sR-zG)/r
Q(z) = (-sR-zG)/r
D = P(z)-Q(z) = 2sR/r != infinity.
```

The group has prime order `n`. Translation by nonzero `D` therefore gives
one cycle of length `n`. Removing the point at infinity and the invalid
pairs touching it does not increase any degree. Canonical compressed point
encoding is injective, so every oracle input is one vertex, with at most two
neighbors in this fixed graph.

For `F=H(P)P+H(Q)Q`, the unknown-nonce coefficient is
`u=(H(P)-H(Q))s/r`. Since `s/r != 0`, the branch `u=0` is exactly a
monochromatic edge. At the moment the second endpoint of any tested edge is
first queried, that new answer is independent of the previous transcript.
There are at most two already-known neighbor colors. If the maximum
single-color probability is `mu`, the conditional chance that this query
completes a successful edge is at most `2*mu`. Union bounding across `Q`
distinct queries gives `min(1,2Q*mu)`, despite adaptive vertex choices.
Arbitrary point queries may be granted free construction cost; any difficulty
in realizing their points as actual transaction digests only restricts the
allowed search further.

The graph must be fixed before point-hash answers are exposed, including
setup answers. Post-hash choice of a source does not satisfy this condition.
A fixed catalogue of `M` sources gives a union graph of degree at most `2M`
and the corresponding bound `min(1,2MQ*mu)`; duplicate edges reduce degree.

For ideal uniform `b`-bit colors, `mu=2^-b`. For an ideal 256-bit hash reduced
modulo `n`, exactly `delta=2^256-n` colors have two preimages and the other
`n-delta` have one, so `mu=2/2^256`. The exact independent-pair collision
probability is `(n+3*delta)/2^512`, but the maximum color mass is the safe
quantity for adaptive queries.

The claimed upper bounds at `Q=2^64` check exactly: `2^-190` for one source
with SHA256 reduced modulo `n`, `2^-158` for a fixed catalogue of `2^32`
sources, and `2^-95` for one source with ideal uniform 160-bit colors.
These refer to tested edges under the stated oracle model.

## Independent finite controls

Sixty-five saved optimal adaptive probabilities agree with closed forms:

- Zero or one query cannot test an edge; two queries achieve exactly `1/c`
  success with `c` uniform colors by choosing adjacent vertices.
- On a cycle of length at least five, three queries achieve exactly
  `2/c-1/c^2`. If the first two vertices are adjacent, a failed first edge
  leaves at most one known neighbor for the third vertex. If they are not
  adjacent, a third vertex may join both: equal neighbor colors yield one
  target color and unequal colors yield two. Both cases give the formula.
- Querying every vertex of a length-`m` cycle gives success probability
  `1-((c-1)^m+(-1)^m(c-1))/c^m`, from the cycle's chromatic polynomial.
  This independently checks the available query-all records.

The audit also reconstructs the catalogue edges explicitly and verifies all
18 recorded maximum-degree bounds. The count of completely enumerated
functions is independently `sum(c^m)=1398` for `m in {3,5}` and
`c in {2,3,4}`. Exact integer fractions reproduce the modulo-reduction color
masses and quoted work-budget bounds.

The final report's postselection control also checks: among eight queried
vertices with 256 colors, the probability of any duplicate is
`1-(256! / 248!)/256^8`, strictly greater than `16/256`. Allowing a shift to
be chosen afterwards connects any such equal pair and therefore invalidates
the fixed-graph bound. The general adaptive collision bound
`binom(Q,2)*mu` still applies to this aggregate's `u=0` branch. At `Q=2^64`,
the saved bounds are strictly below `2^-128` for ideal SHA256 reduced modulo
`n` and `2^-33` for ideal uniform 160-bit colors. The audit checks these
fractions independently as well; none of these color games supplies a
native signature or a funded transaction.

This is an audit of the `u=0` route for the specified hash-weight function.
It is not a lower bound for arbitrary Schnorr signing, arbitrary nonlinear
functions, changing source signatures, or Bitcoin covenants in general.
In particular, `u != 0` only leaves an unknown-point coefficient; it does not
by itself prove that a signing algorithm is impossible.

Reproduce: `python3 research/covenant-2026-09-17/continuation/r21_hash_weight_audit.py`.
