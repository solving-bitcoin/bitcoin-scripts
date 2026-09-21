# R21: hash-weighted canonical pairs and the cost of canceling their unknown scalar

Date: 2026-09-17. Question: can nonlinear, order-independent weights turn
the unique ECDSA recovery pair into a publicly signable, transaction-bound
Schnorr key, avoiding the fixed-coefficient alternatives?

**A hash-weighted pair does evade the fixed-coefficient classification. Its
public cancellation branch requires a hash collision.** For a source
signature fixed before all point-hash queries, the relevant pairs form a
degree-two graph. Their cancellation search has a paired-query bound, not
the ordinary unrestricted birthday count. Choosing the source after hashing
requires a different bound; that case is explicitly retained below.

This is a partial interface analysis. There is no native representation
binding for the aggregate, no general Schnorr signing algorithm for its
nonzero unknown-point component, and no mandatory output reference.
No complete covenant is supplied.

Evidence: `locally-reproduced` for twelve secp256k1 identities and finite
oracle controls; `inspected` for the general derivation. Deployment:
`unclassified`. [Python](r21_hash_weight_cost.py) and
[JSON](r21_hash_weight_cost.json) are standalone host calculations. No
Script/Core execution, native hash witness, library primitive change or
field-library test. Script bytes, witness/hint items, stack/opcode counts
and transaction weights are inapplicable.

## The nonlinear canonical aggregate

Reuse the canonical recovery pair from a fixed source signature `(r,s)`
with exactly two nonce roots `R,-R`:

```
P(z) = (s/r)R - (z/r)G,
Q(z) = -(s/r)R - (z/r)G.
```

Both points must be finite and distinct. The native primitive for obtaining
this unordered pair is prior work; see
[the canonical affine analysis](r21_canonical_affine.md). Use one hash
function on canonical compressed point encodings and interpret its output
as a scalar modulo n:

```
a = H(enc(P)) mod n,
b = H(enc(Q)) mod n,
F = aP+bQ = uR+vG,
u = (a-b)s/r,
v = -(a+b)z/r.
```

Swapping P and Q also swaps a and b. Thus the entire point F is unchanged,
including its y coordinate. Unlike a fixed symmetric linear sum, it can
retain a nonzero R coefficient and depend on z. The twelve real SHA256
vectors at fixed `r=s=1`, `R=lift_even(1)` all have `u!=0`, non-infinity F,
and distinct F values. These are exact host identities; no source nonce
logarithm is computed and no native transaction digest is claimed.

If `u=0`, the aggregate is `vG` with a publicly computable signing scalar,
unless it is infinity. Because r and s are nonzero, cancellation is exactly
`a=b`, a reduced-hash collision on distinct point encodings. If `u!=0`,
knowledge of the scalar f of F would give `log_G(R)=(f-v)/u`. For BIP340's
even-y normalization, use `(epsilon*f-v)/u`, where `epsilon` is the sign
relating F to its even-y representative. This is a reduction from computing
that scalar. It does not state that one Schnorr signature reveals it or
exclude every possible signature-producing algorithm.

Nor does this relation give Script access to u or v, or verify that a raw
CHECKSIG key equals the arithmetically described F. Those native obligations
remain separate from the host point formula.

## A fixed source gives a cycle, not arbitrary collision pairs

Fix `(r,s,R)` before all queries to H, including setup queries. Then

```
D = P(z)-Q(z) = (2s/r)R != infinity
```

is independent of z. Every desired cancellation tests the edge `(X,X-D)`
in the group. Translation by nonzero D has order n, so its undirected graph
is one n-cycle. Excluding infinity and its incident edges cannot increase
the maximum degree of two. We may grant the searcher arbitrary group points
and every z for free; that only enlarges its native-transaction search space.

Let H be an ideal fresh-answer oracle whose most likely scalar value has
probability pmax. A fresh vertex query can complete at most two edges to
previously queried vertices. Those neighbors prescribe at most two target
colors. Conditional on the entire adaptive transcript, the new answer hits
them with probability at most `2*pmax`. Therefore, after Q distinct queries,

```
Pr[any cancellation for a fixed source] <= min(1, 2Q*pmax).
```

Every point-hash query counts, including setup, abandoned candidates, other
uses of the same point-hash domain, and the final verifier's evaluations.
An algorithm that outputs unqueried endpoints must be charged up to two
additional queries to test its output. A bound with Q=0 cannot be applied
to an unchecked guessed pair.

For a catalogue of M sources fixed before those queries, the union graph
has maximum degree at most 2M and the same proof gives `2MQ*pmax`.
This grants every source in the catalogue without charging its construction,
making it an optimistic success bound for that particular family.

For uniform 160-bit colors, `pmax=2^-160`. For uniform 256-bit strings
reduced modulo n, put `E=2^256-n`. E scalars have two preimages and the others
have one, so `pmax=2/2^256`. The exact independent-pair equality probability
is `(n+3E)/2^512`; the larger pmax bound is used for adaptive queries.

| Oracle model and source choice | Success upper bound at Q=2^64 |
|---|---:|
| 256-bit output reduced modulo n; fixed source | 2^-190 |
| Same oracle; catalogue of 2^32 sources fixed beforehand | 2^-158 |
| Uniform 160-bit output; fixed source | 2^-95 |

These are ideal-oracle bounds on the specified cancellation algorithmic
route, not measurements of Bitcoin work or claims about real SHA1
cryptanalysis. No assumption that actual native transaction hashes in
different contexts are independent is needed for this enlarged point-query
game. The ideal point-hash freshness assumption itself remains explicit.

## Post-hash source selection must not inherit the fixed-cycle bound

If the source can be selected after observing hash answers, its shift D
may be chosen to connect two already equal colors. The degree-two proof
cannot be conditioned on that postselected source as though it had been
fixed in advance. The finite control queries eight vertices of Z11 with
256 uniform colors, then permits selecting a nonzero shift after seeing
the colors. Any duplicate suffices. Its exact probability is

```
1 - product_{i=0..7}(1-i/256) > 16/256,
```

which exceeds the inapplicable fixed-source bound. This graph example
does not supply a source signature and an actual funded transaction whose
native digest fits the selected pair.

Even with arbitrary source selection, the cancellation event still requires
equal reduced hashes of two distinct canonical points. A general adaptive
collision bound therefore remains:

```
Pr[any u=0 collision among Q point queries] <= binom(Q,2)*pmax.
```

At Q=2^64 this is below `2^-128` for ideal SHA256 reduced modulo n, and
below `2^-33` for an ideal 160-bit hash. These weaker bounds include source
selection after all setup queries. They remain restricted to u=0 for this
aggregate. Source selection that gives the creator the nonce logarithm
allows signing through u!=0; the collision calculation does not cover that
different route or give it an output restriction.

## Reproductions and remaining constructive target

The executable checks:

- Twelve full-size group vectors, all hash coefficients, both key orderings,
  the fixed translation D and the aggregate decomposition.
- Eighty finite adaptive games on cycles of 3, 5 and 7 vertices, with up to
  five queries and color spaces from 2 to 2^160. Dynamic programming chooses
  the best next vertex for every exposed equality pattern.
- Twenty exact cross-checks against an uncompressed full-color recurrence,
  plus complete enumeration of 1,398 hash functions for query-all controls.
- Eighteen fixed-catalogue games, the postselection counterexample, and all
  exact large probability fractions. The color compression merges only
  exchangeable unobserved colors; it does not assume nonadaptive queries.

A positive continuation needs a transaction-dependent, natively enforced
aggregate whose honest signing algorithm is actually supplied. Nonlinear
canonical weights remain more general than fixed linear coefficients, but
the particular strategy of eliminating their unknown scalar by equal full
hash weights does not give a sub-2^64 route in the stated ideal models.
No conclusion is drawn for another nonlinear function, a correlated hash
construction, or a different native signing interface.
