# R21: the one-short/two-long orbit interface

Question: can one 32-byte hash-derived ECDSA signature and two unrestricted
signatures on native transaction digests enforce a nonce endomorphism
orbit, supplying the missing reference relation without parsing signature
integers or supplying an unbound h?

The new result is an exact interface lemma: a shared public key between
two claimed orbit signatures either equates their normalized coefficients
or publicly determines the base nonce logarithm. If each signature uses
an antipodal recovery pair, a connected graph with no such extraction
collapses to the same two public keys. This identifies precisely what a
different native binding would have to add. It does not give a covenant
or exclude constructions that deliberately make the nonce logarithm
available, use the additional roots of a short-r signature, or use a
different native interface.

For the common-pair case, two long signatures on the same digest cannot
be the two other orbit members. With two independent digest contexts,
the possible ordered digest pairs have support at most about 2^192,
rather than providing a second free choice after the first ratio.
The digest-independence qualification matters; this is a conditional
counting result, not a general native-hash lower bound.

Evidence: `locally-reproduced` for the host-side controls and exact integer
counts; `inspected` for the general algebraic derivations. Deployment:
`unclassified`. [Python](r21_orbit_interface.py) and
[JSON](r21_orbit_interface.json) reproduce the controls. No Script program
is supplied or executed, no signature-hash preimage is found, and no
library field tests are run. Locking-script, witness/hint-item, stack and
opcode measurements are therefore inapplicable.

## A shared-key orbit equation has a public extractor

Work in the prime-order secp256k1 group, with all scalar equations modulo
n. Let R be a finite nonzero base point and let phi(R)=lambda*R. Suppose
signature i reconstructs the nonce

```
U_i = epsilon_i * lambda^j_i * R,
epsilon_i in {+1,-1},
```

under a public key K and its actual native digest z_i. The ECDSA equation
is equivalent to

```
K = a_i*R - b_i*G,
a_i = epsilon_i * lambda^j_i * s_i/r_i,
b_i = z_i/r_i.
```

If signature j is also accepted under K and its nonce has the claimed
orbit relation, subtraction gives

```
(a_i-a_j)*R = (b_i-b_j)*G.                         (1)
```

There are exactly two possibilities:

* If `a_i=a_j`, validity forces `b_i=b_j`.
* Otherwise the public transcript computes
  `log_G(R)=(b_i-b_j)/(a_i-a_j)`.

The signs can be enumerated when only the coordinate orbit is specified.
Equation (1) is a conditional algebraic extractor: the orbit premise must
already be true. Applying the formula to arbitrary valid signatures does
not establish that premise. The controls below explicitly demonstrate
this distinction.

For a graph in which each signature is checked under two distinct keys
and its two reconstructed nonces are the claimed antipodal pair, its key
set is

```
{ +a_i*R-b_i*G, -a_i*R-b_i*G }.
```

At a shared key, absence of a nonzero-denominator extraction forces
`a_i=+/-a_j` and `b_i=b_j`. Thus the entire two-key sets are equal.
Induction along a connected graph collapses all its pairs to one pair.
Adding edges in this exact class cannot impose an independent orbit
coefficient while keeping a distinct connected key arrangement and
avoiding a public nonce-log extractor.

This statement does not assume that an extractor is undesirable or that
the discrete-logarithm problem proves a hash-query lower bound. It is an
exact alternative, not a hardness theorem. It also does not cover a
short-r signature used under a non-antipodal pair from its four roots.
Long signatures of more than 57 bytes have only the antipodal recovery
pair; a short signature needs that pair premise established separately.

## What the common-pair native checks do and do not bind

Let the short signature be `(r0,s0)` on the legacy bug digest `C=2^248`,
and suppose its checks under P and Q reconstruct `R,-R`. A long signature
`(ri,si)` on native digest zi is checked under both of the same keys. Its
two roots are antipodal, so

```
P+Q = -2*C/r0 * G = -2*zi/ri * G,
ri/r0 = zi/C.                                      (2)
```

At the key P its nonce is exactly

```
U_i = (ri*s0)/(r0*si) * R.                         (3)
```

Consequently the additional condition for the two other coordinate
orbit members is

```
si/ri = +/-s0/(lambda^i*r0), i=1,2.                (4)
```

Native checks supply (2), and then (3). They do not separately check (4).
The R11 lattice constructor supplies it off-chain for its chosen witness;
that is not an on-chain obligation for every accepted witness. Comparing
a witness h with 1 or 2 does not add (4).

If `z1=z2`, equation (2) gives `r1=r2`. Genuine secp256k1 coordinate orbits
have distinct r values, including the possible `x=r+n` branches, as
proved in [R13](r13_orbit_query.md). Therefore two long signatures with
the same native digest cannot complete this common-pair orbit.
In particular, repeating CHECKSIG in the same context with the same
ALL flag does not supply the required third orbit member. This conclusion
is specific to the common antipodal pair, not to single-key checks.

## Exact support when the two native digests may differ

A 32-byte DER signature including its flag has `nr+ns=25`, hence
`r0<=M=2^191-1`. With `Delta=p-n<M`, all possible base coordinates belong to

```
X_M = [1,M] union [n+1,p-1],
|X_M| = M+Delta-1.
```

For each x in this set, the oriented coordinate orbit fixes
`(r0,r1,r2)`. Equation (2) then fixes the ordered target pair

```
(z1,z2) = (C*r1/r0, C*r2/r0).
```

Reversing the orientation supplies at most one more ordered pair. Curve
lifting, zero r values, DER restrictions on s, coincident pairs, and long
signature guards can only reduce the support. Thus

```
number of possible ordered (z1,z2) <= 2*(M+Delta-1) ~= 2^192.    (5)
```

For independent uniform canonical scalars this gives a single-pair
probability at most `2*(M+Delta-1)/n^2`, approximately `2^-320`.
For two independent uniform 256-bit strings reduced modulo n, the simple
maximum-multiplicity bound is four times (5) divided by `2^512`,
approximately `2^-318`. No independence between distinct native
transaction contexts is established here, and no generic adaptive
preprocessing or shared-oracle theorem is inferred.

For a *fixed* hash signature r0 there are at most two x lifts and two
orientations, hence at most four ordered digest pairs. A witness choice
of h does not enlarge that set. This strengthens R11's one-target support
calculation specifically for a complete orbit with two long signatures;
it is separate from R14's all-three-short enumeration.

## Constructive controls and the known-nonce alternative

The deterministic positive uses the short coordinate of `R0=(1/2)*G`
already documented in the separate
[point-lock algebra](../../pointlocks-2026-09-17/algebra.md):

```
r0 = 0x3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63,
s0 = 2^24,
q  = (s0/2-C)/r0.
```

The signature `(r0,s0,03)` is exactly 32 bytes. For any digest z and
`ki=lambda^i/2`, ordinary signing with the public fixture scalar q gives

```
ri = x(ki*G) mod n,
si = (z+ri*q)/ki, i=1,2.
```

Both long signatures use the same selected digest in this control, and
all three signatures verify under `q*G`. Their sizes are 32, 71 and 73
bytes, and their reconstructed points form the exact same-y orbit. Both
instances of (1) return `1/2 mod n`. This shows why the common-pair
same-digest exclusion must not be extended to single-key checks.
Adding the companion key `Qi=(-q-2*zi/ri)*G` for each signature gives a
connected three-edge star with four distinct keys. All six ECDSA checks
pass with antipodal nonce pairs. It is an explicit non-collapsed graph
on the extraction side of the lemma, rather than a claimed exclusion of
all larger key graphs.

Two further controls replace the long nonces with `11*G` and `13*G`.
Their ECDSA signatures still verify under the same key, but their points
are outside the signed orbit. Applying the extractor under an invented
orbit premise produces candidates that fail the public point check.
Thus ordinary signature validity has not authenticated the orbit.

Finally, a common-pair positive uses manufactured digests
`zi=C*ri/r0` and `si=ri*s0/(lambda^i*r0)`. It verifies all six equations
under the pair, and all normalized coefficients coincide. These digests
are not claimed to be actual transaction hashes. They are a positive
control for (2)-(4), not a solution of the native-digest obligation.

Knowing the base nonce is therefore a concrete constructive alternative,
but it does not supply the requested hash-derived alpha cheaply. For
this particular fixed r0, a 32-byte signature requires a four-byte DER
s integer. There are exactly `255*2^23` such positive integers. Even
allowing all 256 flag bytes gives only `255*2^31` possible hash outputs,
a probability about `2^-217.0056` for a fresh uniform 32-byte hash.
Allowing the eight flag bytes with low five bits equal to SINGLE gives
about `2^-222.0056`. These are fixed-family ideal-hash estimates only;
the program does not obtain any corresponding hash preimage. The known
half-generator point therefore does not provide a sub-2^64 hash-source
shortcut in this family.

The remaining constructive obligations are still real: either supply a
native enforcement of (4), use a different graph outside the antipodal
pair collapse, or provide a different readable reference relation that
survives retained creator state. No candidate satisfying those obligations
is obtained here.

Reproduce: `python3 research/covenant-2026-09-17/continuation/r21_orbit_interface.py`.
