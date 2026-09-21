# Full subset alphabets cannot linearly deliver arbitrary hidden binary labels

This concerns scalar-linear disclosure, including public correlations. The
[ratio-label extension](ratio-label-reconstruction.md) shows that using
relative logarithms of fixed affine point forms does not compress this
interface, except through publicly recognizable constant labels. This result
excludes replacing the nonlinear 5-of-54 decoder by linear reconstruction,
not nonlinear garbling, point locks or the original publication goal.

## Model

Over any field, candidate scalar i is a public linear form v_i in hidden
setup variables. Quotient out scalar information already public. Point
commitments are not known scalar values. Every t-subset S of N candidates
is admissible and must not reveal an extra candidate scalar: that would
give a complete different t-subset opening by replacing a selected index.

Thus every t+1 candidate forms must be independent. A dependence otherwise
expresses one candidate in at most t others; extend those others to an
admissible t-subset excluding that candidate. This uses public coefficients,
not supposed independence of points in the cyclic elliptic-curve group.

Two fixed output labels may be vectors of forms spanning nonzero subspaces
B0,B1. Total correctness and protection of the opposite full label require
exactly one of B0,B1 to lie in span(S) for every selection S. This describes
any nonconstant binary classifier with two protected linear output labels.

## Proof for N>=t+2

Choose t+1 candidate forms as a basis e0,...,e_t of W. Both output spaces
must lie in W. If one did not, all t-subsets of this basis would have to
contain the other, placing it in their zero intersection, a contradiction.

Let I_b be the union of basis coordinates used by forms in B_b. Omitting
coordinate j leaves B_b available exactly when j is not in I_b. Exactly one
label must remain available for every j, so I0,I1 partition all coordinates
into two nonempty sets.

Take an extra candidate w, choose i in I0 and j in I1, and select

```
S = {w} union {e_k : k != i,j}.
```

If w is outside W, span(S) intersects W only in the remaining coordinates.
It contains neither B0, which uses i, nor B1, which uses j.

If w is in W, all its coefficients are nonzero: a zero coefficient would
make w and t basis candidates dependent. Any vector in span(S) has omitted
coordinates alpha*(w_i,w_j). B0 contains a vector with nonzero i and zero j;
B1 contains one with zero i and nonzero j. Neither fits that form, so again
neither full output label is available. This contradicts total evaluation.

The proof includes correlated candidates and vector outputs. Its boundary
is tight: [N-1-of-N complement lookup](../../research/pointlocks-2026-09-17/shared-vector-gates.md)
supports every nonconstant binary classifier with public point checks and
one-opening privacy for independently generated scalar keys.

## One protected output: a separate coverage bound

If only one output needs protection, the two-label theorem does not apply.
There is still a bound on selections that reconstruct a nonpublic fixed
scalar-linear secret c.

If c is proportional to a candidate, exactly the subsets containing that
candidate reconstruct it. Any other such subset would create a dependence
among t+1 candidates. Coverage is C(N-1,t-1) of C(N,t) selections.

Otherwise project the candidate forms modulo span(c). No projected candidate
is zero. A reconstructing t-subset has projected rank t-1. Its unique
dependence has at least two nonzero coefficients, so deleting either of
those elements gives an independent projected (t-1)-subset. These supply
at least two distinct certificates for each reconstructing subset.

No certificate belongs to two reconstructing t-subsets: their t+1-element
union would project to rank t-1 and have original rank at most t, contradicting
subset privacy. There are at most C(N,t-1) certificates in total. Coverage
is at most floor(C(N,t-1)/2). For a vector output, applying this argument to
any nonzero component bounds recovery of the complete vector too.

At N=54,t=5 the two cases give 292,825 and 158,125 selections out of
3,162,510, respectively: 5/54 or below 5%. This does not classify every
possible one-output predicate or exclude a different message encoding.

## Connection, scope and evidence

For the current 95-pool modulo-2^2048 decoder, changing one pool's subset
always changes the message: B=3,162,510 has 2-adic valuation one, and the
valuation of any nonzero single-pool rank change times B^i is at most 115.
It cannot vanish modulo 2^2048. Thus the extra-candidate disclosure used in
the model really permits another message there. Multi-pool aliases remain.

The results exclude nonlinear recovery, encrypted shares, additional secret
authentication inputs, different admissible selection families and different
native disclosure mechanisms. They do not identify all algebraic computation
with scalar-linear operations. General native extraction remains unresolved.

Evidence: **inspected** proofs and **locally-reproduced** controls in the
[report](../../research/pointlocks-2026-09-17/shared-vector-gate.json). Ten tests
include correlated Vandermonde cases, all target directions in the stated
small fields, 480 constructed extra-column contradictions, support enumeration
and 70 curve evaluations of the tight complement construction. Deployment:
**unclassified**. No new Bitcoin script, witness/hint/stack metric, transaction,
Core result or setup benchmark is claimed.
