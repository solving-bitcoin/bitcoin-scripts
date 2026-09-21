# Shared-key graph authentication

This branch asks whether native ECDSA can authenticate many selectable points
using fewer committed public keys, escaping the explicit one-entry-per-point
representation. The construction below is algebraically useful, but does not
establish a sub-100,000-vbyte publication scheme.

## A signature authenticates an edge

Let vertices be public keys `A_i=a_i G`. An edge `(i,j)` has target
`T_ij=A_i+A_j`. The same guarded ECDSA signature under both distinct endpoint
keys reveals the scalar of that target: `a_i+a_j=-2z/r (mod n)`, with the
usual signature-length guard above 57 bytes excluding the alternate `r+n`
nonce-coordinate case. This is the existing sum-key theorem applied to a
shared graph rather than a star with common endpoint `G`.

For honest setup choose a nonce `k_e`, set `r_e=x(k_e G) mod n`, and set
`y_e=-2C/r_e`. If vertex scalars satisfy `a_i+a_j=y_e`, then
`s_e=(C+r_e*a_i)/k_e` signs the constant native digest `C=2^248` under both
endpoints. The signature may be normalized to low S. Adjacency must also be
authenticated: accepting any pair of table vertices does not make every pair
an honestly constructible member of the advertised alphabet.

Knowing both endpoint private keys does not solve arbitrary edge setup: their
sum fixes `r`, and obtaining a nonce with that x-coordinate is another discrete
logarithm problem. This is why a complete graph cannot simply be filled in by
ordinary signing.

## Trees and odd cycles are constructive

A tree is built by fixing one root scalar and choosing each edge nonce freely;
its new neighbor is `a_j=y_e-a_i`. Each edge adds one vertex. This gives no
commitment saving over the current star.

An odd cycle needs no nonce search when its root scalar is free. For a triangle:

```
a_0 = (y_01+y_20-y_12)/2
a_1 = y_01-a_0
a_2 = y_20-a_0
```

Thus three independent nonce-derived edge scalars yield three endpoint keys and
three valid double-check signatures. Check nonzero/distinct vertex keys and
nonzero edge targets. An odd cycle has one vertex per edge, so it still does not
compress candidate commitments, and a selected edge needs both endpoint keys
or equivalent table references.

For a connected bipartite graph the endpoint-sum incidence matrix has rank
`V-1`; for a connected non-bipartite graph it has rank `V`. Consequently, dense
setup requires respectively `E-V+1` or `E-V` independent scalar constraints on
the independently nonce-derived edge values. One successful cycle relation
does not supply all relations of a dense graph.

## A possible expensive even cycle

A 16-edge even cycle closes when the alternating sum of its edge values is
zero. Applying a generalized-birthday construction to sixteen independent
nonce lists suggests list lengths around `2^(256/5)`, and around `2^55.2`
nonce/curve operations in total before constants. This is a heuristic modular
sum adaptation of [Wagner, CRYPTO 2002](https://people.eecs.berkeley.edu/~daw/papers/genbday.html),
not an implemented setup algorithm or a measured cost. Distribution, modular
carry handling, very large memory, and concrete success probability remain
unverified.

After closure, choosing root scalar one derives all sixteen vertex scalars.
The graph then stores fifteen non-generator vertices for sixteen edges, a
6.25% reduction in this table component. Eight-list asymptotics already cost
about `8*2^64`, above the stated total budget. These estimates count curve work,
not merely hash compressions, and do not make the 16-edge construction practical.

Every closure also creates a public relation among target scalars. For example,
revealing fifteen edges of the even cycle determines the last edge. A message
code must account for this closure instead of treating all edge labels as
independent one-time secrets. Endpoint authentication, adjacency, subset
uniqueness, transaction framing, and all script limits still need a concrete
implementation before quoting a publication size.

Evidence: **inspected** algebra and conditional setup estimates. Deployment
class: **unclassified**. No curve collision search, compiled graph script, peak
stack, hint count, witness metric, or Core validation is claimed. The useful
positive primitive is edge authentication by shared endpoint keys; a graph
family that makes it economical under the stated work and soundness constraints
has not been established here.
