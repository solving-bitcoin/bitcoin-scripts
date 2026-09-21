# Endpoint graphs: cheap cycles, closed choices, and the remaining setup equation

Question: can a graph of shared ECDSA verification keys encode an arbitrary
future 256-byte proof below 100,000 vB for creation plus spending, with purely
algebraic noninteractive setup below `2^64` work and no ZKP?

The search below does not produce such a construction. It does give a cheap
odd-cycle setup, verifies a useful closed choice family, and narrows the
missing step: the graph needs substantially more edges than vertices, with
many simultaneously prepared, distinct inverse-coordinate labels. The usual
endomorphism orbit and repeated-nonce shortcuts do not supply those labels.

The deterministic [program](endpoint-graph-search.py) and
[result](endpoint-graph-search.json) are `locally-reproduced`; deployment is
`unclassified`. They check host ECDSA equations, symbolic linear spans and
exact byte relaxations. There is no new Script, Core execution or complete
publication. Script bytes, stack peaks, hint counts and execution opcodes
therefore are not measured for a new primitive. The byte figures below
explicitly omit those obligations.

## The candidate graph and its honest openings

For each vertex commit a compressed key `P_v=p_v G`. An edge `{u,v}` uses
the same signature `(r,s)` under its two keys and the common native digest C.
With distinct endpoints and the existing signature-length guard excluding
mixed `r` and `r+n` lifts, its target is

```text
T_e = P_u+P_v,             t_e = p_u+p_v = -2C/r_e mod n.
```

Consequently the endpoints represent an implicit list of edge labels.
For a freely selected secret nonce `k_e`, put

```text
r_e = x(k_e G) mod n,
t_e = -2C/r_e mod n,
s_e = (C+r_e p_u)/k_e mod n.
```

If `p_u+p_v=t_e`, the signature verifies under both endpoints, using opposite
nonce points. The setup problem is therefore the linear system
`A p=t`, where A is the graph's signless edge-vertex incidence matrix, **plus**
the requirement that every t came from an available known nonce.

A connected bipartite graph has rank `V-1`; a connected nonbipartite graph
has rank V, over the odd prime-order scalar field. This follows directly by
examining the kernel equations `p_u=-p_v`: a bipartite component leaves one
free alternating value; an odd cycle forces that value to zero.

This improves the earlier tree-only observation. An odd unicyclic component
can prepare **E=V arbitrary nonce-derived edge scalars without a search**.
For a triangle with edge values `t01,t12,t20`, use

```text
p0 = (t01-t12+t20)/2,
p1 = (t01+t12-t20)/2,
p2 = (-t01+t12+t20)/2.
```

The reproduction chooses deterministic secret fixture nonces 7, 19 and 31,
constructs all three endpoint keys and verifies all six ECDSA equations.
These public test secrets are not production setup material. The triangle
does not compress the label list: three stored keys represent three labels.
More generally, E≤V constructions do not beat the ideal explicit-list bound.

Every edge beyond the appropriate incidence rank needs an additional exact
relation among nonce-derived t values. For a bipartite cycle this is an
alternating sum. For example, a four-cycle requires

```text
1/r01 - 1/r12 + 1/r23 - 1/r30 = 0 mod n.
```

Free signature s values do not change this equation. A longer cycle can
offer a generalized birthday search, but adding many cycles requires many
compatible equations, not many independent uses of one solved cycle.

## Which graph choices really encode different messages?

Use the public incidence vectors of the selected edges to describe the
linear combinations of endpoint secrets exposed by their scalar labels.
An unselected edge in that span is already derivable. In particular, two
spanning trees of the same component cannot count as different messages.

A constructive family survives this check: in a bipartite a-by-b graph,
select exactly one neighbor for every left vertex. Each selected component
is a star with a single right vertex. With no additional public relations
among endpoint secrets, its closure contains exactly those selected edges.
For a complete graph there are `b^a` such assignments; the right choices
need not be distinct. Exhaustive modular row reduction verifies all 27
assignments of the complete 3-by-3 graph. A separate square fixture verifies
that revealing three edges derives its fourth.

Thus a dense grid has a valid combinatorial use; the outstanding issue is
preparing every edge opening. Sparse stars and trees have cheap openings,
but their explicit number of independent edges gives no information gain.

## Sparse graphs already miss the byte target in an optimistic relaxation

Suppose a graph has V embedded endpoints, E candidate edges and t selected
signatures. Count **all** `binomial(E,t)` subsets, even those whose closures
make them unsuitable. Charge only 34 bytes per key push and 72 per pushed
71-byte signature. Omit every verifier, selector, funding output, input
header, script wrapper and transaction header. Minimize

```text
34V+72t,       binomial(E,t) >= 2^2048,       E/V <= rho.
```

The exact integer minima are:

| Maximum E/V | V | E | t | Relaxed bytes |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 2,297 | 2,297 | 714 | 129,506 |
| 8/7 | 2,046 | 2,338 | 696 | 119,676 |
| 4/3 | 1,797 | 2,396 | 674 | 109,626 |
| 3/2 | 1,638 | 2,457 | 654 | 102,780 |
| 2 | 1,298 | 2,596 | 617 | 88,556 |
| 3 | 961 | 2,883 | 563 | 73,210 |
| 4 | 774 | 3,096 | 534 | 64,764 |

In particular, an average-degree-at-most-three graph cannot cross 100,000
bytes even under this relaxation. High girth by itself does not help that
accounting. The smallest density admitting any relaxed sub-100,000 point is
`E/V=2457/1556≈1.579049`: V=1,556, E=2,457 and t=654 cost 99,992 bytes.
There is no room for actual Script or transaction overhead at that point.
These are bounds for this embedded-endpoint, 71-byte-signature family;
shorter signatures or a different representation change the model.

The closed one-neighbor-per-left construction needs still greater density.
For a homogeneous left degree d it has a·log2(d) bits, while the same relaxed
cost is at least `a·(34d/rho+72)`. At rho=4/3 the best integer degree is five,
costing about 85.92 bytes per bit before verification. At rho=4, degree eight
costs about 46.67 bytes per bit, approximately 95,574 bytes for 2,048 bits
before rounding or overhead. This motivates genuinely dense setup, rather
than a sparse graph with a large abstract number of spanning trees.

## Why the immediate nonce tricks do not create the needed density

**Reusing a nonce or its negative.** The x-coordinate, r and target scalar t
are identical. Assigning that value to many graph edges does not create many
independent point labels. Constructing free cycles by duplicating edge
values can be algebraically valid while providing no corresponding message
capacity. If a nonce is public, its t is public before publication as well.

**Making nonce addition implement label addition.** The map
`f(k)=-2C/x(kG)` is even: `f(k)=f(-k)`. A nonzero additive map from the odd
prime-order nonce group to its scalar field cannot be even. Thus the simple
proposal `f(k+l)=f(k)+f(l)` cannot be an identity; known nonce addition does
not automatically solve the cycle equations. This excludes that identity,
not isolated solutions or more complicated algebraic preprocessing.

**The three-point endomorphism orbit.** It gives `R_j=lambda^j R` and
`x0+x1+x2=h·p`, with h=1 or 2. It does not give an alternating sum of
`1/r_j` modulo the different group order n. The reproduction records an
explicit nonzero inverse-coordinate sum for the nonce-seven orbit. The
exact field/order wrap is treated in
[R11](../covenant-2026-09-17/continuation/r11_endomorphism.md); dropping it
would manufacture a false setup relation. A sample disproves the proposed
universal identity, but does not rule out specially chosen orbit instances.

There is also a precise obstacle to a common unknown-log construction.
Suppose keys are built symbolically as `P_v=a_v X+b_v G`, a connected graph
uses nonce points `R_e=c_e X` with known c, and signatures are produced by
matching these known coefficients without finding `log_G(X)`. An edge forces

```text
a_v = -a_u,              b_u=b_v=-C/r_e,
s_e/r_e = a_u/c_e.
```

Every edge incident at a shared vertex therefore has the same r. A pure
endomorphism family, whose three r values are distinct, cannot use this
coefficient-matching construction to connect the orbit into a dense graph.
This is a statement about that symbolic construction, not mathematical
linear independence of X and G: the actual curve group is cyclic.

Adding known nonce translations `R_e=c_e X+d_e G` removes that immediate
equality but leaves

```text
b_u+b_v = -2C/r_e,
b_u-b_v = 2a_u d_e/c_e,
r_e = x(c_e X+d_e G) mod n.
```

The first equation is still exactly the inverse-coordinate graph problem.
The free width s and the known translations do not by themselves solve
the shared-vertex compatibility equations. Choosing X with a known scalar
returns to the known-nonce setup problem above.

The existing [R13](../covenant-2026-09-17/continuation/r13_orbit_query.md),
[R14](../covenant-2026-09-17/continuation/r14_orbit_binding.md) and
[R18](../covenant-2026-09-17/continuation/r18_endomorphism_resultant.md)
exclude other specific native-orbit shortcuts. Their three/four-common-key
results are not silently applied to this two-endpoint graph construction.

## What an actual next breakthrough must provide

A useful next result is a reproducible graph whose distinct usable labels
outnumber its endpoints by enough to pay verification and framing, together
with openings for every permitted edge and a closed, sufficiently large
message family. The odd-cycle construction meets honest setup but not size;
the dense grid meets the abstract access-structure objective but lacks the
required honest setup.

As a heuristic only, if at most `2^b` known-nonce scalars form a random subset
of the scalar field, a graph of incidence rank d has about
`2^[256d-(256-b)E]` nondegenerate labelings whose distinct edge values all
belong to that set. At b=64 this favors E/d≤4/3, below even the relaxed
109,626-byte row. Degenerate repeated labels, structured nonce relations and
adaptive preprocessing are outside that random-subset model. It is not an
impossibility theorem or a substitute for trying a concrete algebraic family.

Reproduce only this bounded host experiment:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/endpoint-graph-search.py
```
