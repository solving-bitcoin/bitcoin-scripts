# Counting shared orbit keys together with their disclosure

Question: does the 96,549-vB optimistic two-key row in the
[earlier sharing bound](orbit-key-sharing.md) leave a viable fixed-orbit
publication route? **Not in that explicit-inventory model.** Accounting for
which keys can actually be shared gives a **110,865-vB** floor for fixed
two-key packets and 40-byte openings, even before privacy is required.
Accounting for the known scalar disclosure gives a **116,643-vB** floor.
All transaction, authorization, lookup and verification overhead is still
granted free. These results close a representation loophole, not the original
research goal.

[Executable probe](orbit_private_sharing_bound.py),
[results and source hashes](orbit-private-sharing-bound.json).

## Model and scope

Use the globally fixed r0=2 construction, with the two ECDSA lifts R0,R1 and
canonical scalar labels s. Public commitments contain the full orbit
O(s)={+/-sR0,+/-sR1}. Script verification keys are its affine transforms
Q_H=(H-CG)/r0. The previous argument establishes that every key has at most
two distinct canonical label owners. All label orbits are distinct.

Grant one raw 20-byte commitment per inventory label, authenticating its
whole packet for free, and one raw L-byte opening per selected label. Charge
only distinct supplied compressed keys, at 33 bytes each. The signature
profile is an explicit assumption, not a universal DER lower bound. Grant
that checking just two distinct orbit keys would suffice for correct
extraction: no such native predicate is supplied here.

Messages are selections of distinct protected scalar labels. Ordering the
same scalar disclosure does not provide another privately bound message.
All required onchain data in this model has legacy weight. Hash-preimage
binding, lookup opcodes, pushes, duplicate-key reuse, transaction framing,
outputs, input headers and authorizations are free in these lower bounds.

The graph-only result assumes a fixed two-key packet per label. It also
applies when a fixed larger packet always has to be supplied: choose any
two of its keys for the bound and ignore the rest. A spend-dependent choice
of two keys from a larger packet is not covered by that graph proof.
The privacy result instead uses the full public orbit-sharing graph and
only requires at least two distinct supplied orbit keys per selected label.

Implicit alphabets, a different scalar/label interface, varying global root
parameters, a new SegWit setup, and an additional secret authentication
input that changes the message interface are outside these results. In
particular, these are not lower bounds on every Bitcoin point lock.

## Key reuse has a graph cost, not just an incidence cost

For a fixed two-key packet, give each label a vertex and each shared key an
edge joining its two owners. Private keys in this paragraph mean keys owned
by only one packet, not secret signing scalars. A vertex has degree at most
two. The multigraph has paths, isolated vertices, and cycles; two distinct
labels sharing both keys form a two-vertex cycle with parallel edges.
No key can create a self-loop or have three owners.

For a selection S, let e(S) count shared-key edges with both endpoints in S,
including parallel edges. The number of distinct supplied keys is exactly
2|S|-e(S). Its optimistic cost is therefore

```
c(S) = 20N + (66+L)|S| - 33e(S).
```

For any positive R define

```
w0 = 2^(-20/R)
w1 = 2^(-(86+L)/R)
q  = 2^(33/R)
M  = [[w0, sqrt(w0*w1)], [sqrt(w0*w1), w1*q]].
```

The sum of 2^(-c(S)/R) over all selections is a product of component
partition functions. For a cycle of m>=2 vertices the factor is tr(M^m).
Both eigenvalues of M are nonnegative, since its determinant is
w0*w1*(q-1)>=0. Consequently

```
tr(M^m) <= tr(M^2)^(m/2).
```

For a path with m vertices the factor is v^T M^(m-1) v, where
v=(sqrt(w0),sqrt(w1)). The operator norm of M is at most sqrt(tr(M^2)),
and ||v||^2=w0+w1<=sqrt(tr(M^2)). Thus the same bound holds for paths,
including isolated vertices. This proves the bound for every such
multigraph, not only the graphs enumerated by the probe.

Choose R so that

```
tr(M^2) = 2^(-40/R)
        + 2 * 2^(-(106+L)/R)
        + 2^(-(106+2L)/R) = 1.
```

Then the full selection mass is at most one. If 2^2048 distinct messages
each cost at most B, their mass is at least 2^(2048-B/R); hence B>=2048R.
For L=40, R=54.13300068915869865... vB/bit and the integer bound is
**110,865 vB**. The earlier 96,549-vB incidence relaxation had granted
maximal reuse for every selected set simultaneously. The graph calculation
accounts for the fact that isolated selected vertices cannot receive that
discount.

Parallel-edge components attain equality in this counting relaxation.
They are granted for a stronger bound on a more permissive model; this does
not show that identical two-key packets would correctly distinguish two
different labels in a native construction.

## Privacy restricts selections across components

Now use the graph of full orbit overlap, not just the two checked keys.
Let R1=rho*R0. The earlier algebra proves that opening two adjacent,
distinct labels reveals rho. With rho known, any already opened scalar
opens every inventory label in its connected component by repeated
multiplication or division by rho and comparison to public orbit packets.

There is only one global rho. Opening an edge in component A therefore
also enables propagation from an opened label in component B. It is
insufficient to select all of A while selecting just one label of B.

Suppose an accepted selection must not reveal any unselected scalar label.
Every permitted selection then belongs to the union of two families:

* I: independent sets of the full overlap graph. No selected pair overlaps.
* U: unions of entire connected components. If any edge is selected, every
  component touched by the selection must be selected in full.

This is only a necessary privacy condition. No selected edge means that
this particular ratio-recovery argument does not apply, not that all other
ways of recovering rho have been excluded. The proof deliberately grants
all independent sets to obtain an optimistic capacity bound.

For I there is no supplied-key reuse. Therefore

```
c(S) >= 20N + (66+L)|S|.
```

Let R solve 2^(-20/R)+2^(-(86+L)/R)=1. The selection mass of I is at most
one, by summing over all subsets and factoring over vertices.

For U, factor instead over components. A singleton costs at least 20
unselected and 86+L selected. A component of k>=2 vertices costs at least
20k unselected and (53+L)k selected: its k signatures cost Lk, and its
2k key occurrences require at least k distinct keys. Both of these state
costs are no smaller than the corresponding singleton costs. Every
component's two-state mass is therefore at most one, and the total mass
of U is at most one.

The mass of I union U is at most two, even allowing overlap between the
families. Covering 2^2048 distinct messages with maximum cost B requires

```
2^(2048-B/R) <= 2,       hence B >= 2047R.
```

| Opening profile L | Graph-only bound, fixed two-key packets | Privacy bound, at least two checked orbit keys |
|---:|---:|---:|
| 40 B | 110,865 vB | **116,643 vB** |
| 13 B | 92,876 vB | **100,291 vB** |
| 12 B | 92,170 vB | 99,664 vB |

The last row is not a proposed optimization. At r0=2, a <=12-byte opening
has at most four DER bytes for its scalar and hence canonical s<2^31.
Likewise, the 40-byte row describes full-width openings; it is not silently
charged to every shorter DER encoding. Different opening-length distributions
would require corresponding accounting and hiding arguments.

## Executable evidence

Four focused test methods pass. Six bounded graph profiles enumerate all
**1,030 selections**, including isolated vertices, paths, cycles, parallel
edges and disconnected components. They check exact key counts, disclosure
closure and the I-or-U classification. Finite partition sums reproduce the
analytic inequalities; those sums use floating-point tolerances and do not
replace the proofs. Numeric rate brackets use 90-digit Decimal arithmetic
and 200 bisection steps; both endpoints yield each reported integer ceiling.

Three additional curve controls use the actual secp256k1 group with
synthetic bases (R0,7R0), two three-label components and one isolated label.
Opening all of the first component and one label of the second recovers
both missing labels of the second. Whole-component selections are closed
under the demonstrated propagation. These are not ECDSA root sets, native
spends or claims of general privacy for those controls. The actual r0=2
root ratio remains unknown.

Evidence: **inspected** analytic arguments and **locally-reproduced** finite
controls. Deployment: **unclassified**. No new Script, transaction, setup
benchmark, witness or hint-item count, stack peak, or opcode metric is
claimed. No Bitcoin Core or tapscript/unlimited-stack execution is used.
Existing native byte counts remain unchanged.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/orbit_private_sharing_bound.py -v
```
