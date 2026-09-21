# R11: a free-signature solver is not yet a hash-root reference

Date: 2026-09-17. Question: if a known endomorphism realizes the R10
cross-signature ratio without individual nonce logarithms, does the same
method supply alpha as a hash of a readable reference? The comparison counts
both hash-root generation and actual native digest queries, including setup.

The [endomorphism investigation](r11_endomorphism.md) studies choosing a free
signature after a native digest is known. This note isolates the additional
constraint when alpha must be a native 20- or 32-byte hash result. It is a
bounded calculation for a fixed catalogue of nonce multipliers, not a lower
bound for every nonce solver or covenant construction.

Evidence: `locally-reproduced` for the exact small-curve enumeration and
finite-oracle experiment; deployment `unclassified`. Large hash-search
figures below are explicitly idealized model bounds. No Script, native
hash-derived signature witness, Core result or covenant is supplied here.
Locking/witness sizes, hint counts and stack/opcode metrics are inapplicable
to this host calculation. No library files or field-library tests changed.

## Two fixed endomorphisms give at most four targets per alpha

Let C be the SINGLE-bug scalar, r the numerical r in alpha, and R a recovery
nonce point. For one of the two nonidentity endomorphisms phi, the known
scalar multiplier lambda permits

```
R_beta = phi(R) = lambda R,
r_beta = x(phi(R)) mod n,
s_beta = r_beta*s_alpha/(lambda*r),
z_target = C*r_beta/r                 mod n.
```

The two signs of R give the same r_beta. There are at most two x coordinates
for r (`r` and `r+n`) and two nonidentity endomorphisms, hence at most four
scalar targets per fixed alpha. Low-S normalization and the negative versions
of those multipliers do not add targets. Some branches do not lift, some
produce invalid r_beta=0, and some targets coincide, so four is an upper bound.

This target set can be computed without knowing either nonce logarithm.
That improvement does not make a previously fixed r freely selectable.
The catalogue analysis grants all four candidates and imposes no additional
cost for recovering or validating their points.

## Exact short-DER x strips

A strict DER signature plus one flag byte of total length L satisfies
`len(r)+len(s)=L-7`. Since s occupies at least one byte and a positive DER
integer's top bit is zero, the largest numerical r is

```
L=32: r <= 2^191-1,
L=20: r <= 2^95-1.
```

Padding with a leading zero does not increase either maximum. For a bound
`1<=r<=Rmax<n`, the possible nonce x coordinates are the two intervals

```
[1,Rmax] and [n+1, n+min(Rmax,p-n-1)].
```

They contain `Rmax+min(Rmax,p-n-1)` integers before curve-lift filtering.
Thus the two-endomorphism target support across *every* such r is at most
twice that number. In the uniform scalar model the support fraction is
approximately `2^-64` for 32-byte signatures and `2^-159` for
20-byte signatures. These are upper bounds on available target sets, not
claims that hashing into one supplies a hash preimage with the right r/s.
For actual 256-bit digests reduced mod n, some scalars have two representations;
using the conservative factor-two bound weakens these exponents by one bit.

The short-r strips must be imposed in a hash-first lattice construction.
A freely found full-width nonce x coordinate is not automatically compatible
with a 32-byte hash-derived alpha. Conversely, finding a short x still does
not supply a preimage for a DER signature containing that r.

## Counting the two hash lists

Assume distinct independent ideal-oracle domains for fresh root outputs and
fresh native transaction digests. Fix the catalogue to the two endomorphisms
above. Let Q_H root queries and Q_Z native digest queries include every setup
query. Use the optimistic syntax-only probability

```
p_DER = 780555/2^65
```

for a uniform 32-byte root. Recoverability, SINGLE flags and a valid intended
reference may reduce it. Each valid root supplies at most four native scalar
targets. Any particular scalar has at most two 256-bit representatives.
The expected number of matching root/digest pairs, and hence the success
probability, obeys the union bound

```
Pr[any pair] <= Q_H*Q_Z*p_DER*8/2^256.
```

The ordering of queries does not grant a free list: under the stated
independent fresh-output assumptions each cross-domain query pair has the
same joint distribution, including when its query inputs depend on previous
answers. The output-dependent target selection is restricted to the fixed
catalogue. A new scalar-map search chosen after both outputs, reused query
inputs across domains, or structural equality between real hash calls requires
a separate argument and is not covered by this model.

With **fixed caps** `Q_H=Q_Z=2^63`, the bound is approximately `2^-172.43`.
Treating native scalars as exactly uniform modulo n instead gives about
`2^-173.43`. But an adaptively divided total budget must not simply substitute
`Q_H*Q_Z<=Q^2/4` into a syntax-weighted expectation. The independent review
caught that distinction: with three total queries, root until the first
valid answer and then native queries can outperform the fixed-cap bound.
For p=1/4 and native hit probability a=1/8, its exact success is 21/256,
larger than the invalid substitution `floor(3^2/4)*p*a=1/16`.

For a safe adaptive bound, couple the two independent domains to infinite
fresh-answer sequences R_i and Z_j. Any pair observed within Q total queries
has `i+j<=Q`. There are `Q(Q-1)/2` such index pairs, so

```
Pr[any pair within adaptive Q] <= Q(Q-1)/2 * p_DER * 8/2^256.
```

At `Q=2^64`, this is approximately `2^-171.43`. It includes adaptive domain
allocation under the stated fresh-independent-answer model. These figures
are not total-work estimates for the free-signature lattice solver and do
not refute it.

## Deterministic checks

Run

```
python3 research/covenant-2026-09-17/continuation/r11_endomorphism_root_cost.py
```

The [JSON](r11_endomorphism_root_cost.json) enumerates the endomorphisms on
the separate toy curve `y^2=x^3+7 mod 211`, group order 199, generator (3,33).
It checks all 198 nonempty r-strip bounds against the actual target sets.
A separate 16-symbol ideal root oracle has four valid root classes. Complete
enumeration of two root queries and one native scalar query checks success
probability, expected pair count and the union bound separately. An additional
1,024 outcomes check the adaptive-allocation counterexample above. This toy
alphabet is not Bitcoin DER encoding. The large exact integer products and
DER maxima are recorded separately from this finite experiment.

The remaining constructive question is a native relation that preserves a
large real hash-root domain while binding the intended outputs. A free-alpha
solver, short-r support, and a completed reference hash preimage are three
different obligations.
