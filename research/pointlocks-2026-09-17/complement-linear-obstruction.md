# A scalar-linear obstruction to threshold-complement labels

Question: can the encrypted threshold-complement table be replaced with public
linear equations, while preserving one scalar per candidate and preventing
extra openings? **Not for n >= t+2 in the scalar-linear model below.** This
is stronger than the previous randomly chosen affine-mask counterexample,
but is not an impossibility theorem for the user's full objective.

## Model and statement

Work over any field. Let v_i be the linear form defining candidate scalar x_i
in a common vector of hidden field values. Quotient out any already public
scalar-linear information; affine constants are known and can be subtracted.
Let z_j define a zero-label scalar Z_j. Hashing a recovered Z_j into a garbled
label does not prevent the recovery described here.

Require all of the following for every t-element set S:

1. For j outside S, x_j must remain unrecoverable by linear operations on
   the selected scalars: v_j is not in span{v_i : i in S}.
2. For j outside S, its zero-label must be linearly reconstructible:
   z_j is in span{v_i : i in S}.
3. For j inside S, its zero-label must remain unavailable:
   z_j is not in span{v_i : i in S}.

Condition 1 protects the unopened one-labels. Condition 3 prevents obtaining
both labels at a selected position. If a common free-XOR offset is used, even
one such pair exposes that offset and all alternatives.

These conditions cannot hold simultaneously when n >= t+2 and t >= 1.
They cover a direct scalar-linear delivery layer with public linear data;
they do not cover encrypted PRF pads, nonlinear decoding, group-valued DH
labels, or a different access structure. Curve commitments and label hashes
are not being treated as publicly available discrete logarithms.

## Proof

Condition 1 implies every t+1 candidate forms are independent. Otherwise,
one nonzero coefficient in a dependence expresses that candidate using at
most t others; pad that set to t if necessary, violating condition 1.

Fix j. Choose a set U of t-1 indices excluding j, and two further distinct
indices a,b excluding both U and j. This is possible because n >= t+2.
Correctness for the two selections U union {a} and U union {b} requires

```
z_j in span(U,a) intersect span(U,b).
```

The t+1 forms in U union {a,b} are independent. Consequently the intersection
is exactly span(U). But then z_j is also in span(U,j), where j is selected.
This contradicts condition 3. The argument includes t=1: U is empty, so z_j
would be public.

The boundary is tight for these conditions. At n=t+1, choose independent
x_0,...,x_t and set Z_j=sum_{i != j} x_i. The sole t-element selection excluding
j recovers Z_j. Any t-element selection containing j misses one summand and
cannot recover it, nor can it recover the unselected x_i.

This boundary has only n=t+1 subset messages. It does not supply the large
4-of-50 alphabet required by the compact publication prototypes.

## Reproduction and implication

[Source](complement_linear_obstruction.py) and
[report](complement-linear-obstruction.json) check exact examples for t=1..5
over F_101. Vandermonde candidate forms reproduce the independent t+1 case,
the intersection dimensions and the selected-zero recovery. Independent basis
forms reproduce every selection at the tight n=t+1 boundary. A short dependent
example reproduces the alternative failure of exposing an unselected scalar.
These finite examples are regression evidence, not the proof of the theorem.

The [earlier affine-mask counterexample](complement-linear-mask-counterexample.json)
recovers all eight candidate scalars by eliminating the public scalar equations.
Making that matrix rank deficient is not, by itself, a repair: if the resulting
construction still belongs to this model and supplies all required complements,
one of the three conditions must fail.

The current [PRF-encrypted construction](complement-translation.md) is outside
this model and its honest label delivery remains intact. It still lacks public
malicious-setup verification. A successful repair needs additional structure,
not just a different public scalar-linear mask matrix.

A separate [binary-output rank bound](binary-linear-label-rank.md) addresses
direct linear delivery of the final message's k binary labels. Full-cube
one-message privacy forces every selected label set to have rank k, even if
the label masks were deliberately correlated. At least k field openings are
then required. This is a different interface from the threshold-complement
statement above; the nonlinear garbled message decoder is outside both direct
scalar-linear models.

Evidence: **inspected** proof, **locally-reproduced** examples. Deployment:
**unclassified**. This changes no Bitcoin code or onchain resource count and
claims no full-protocol extraction or garbling result.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/complement_linear_obstruction.py
```
