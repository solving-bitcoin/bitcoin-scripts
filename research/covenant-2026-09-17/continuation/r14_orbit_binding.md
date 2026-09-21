# R14: two denser native orbit-binding graphs

Question: can prescribed affine-orbit keys, or four shared recovery keys,
force a useful three-point nonce orbit while retaining full-size signatures?

Two concrete graph templates have exact obstructions. A single ECDSA
signature cannot verify under three distinct keys of an affine lambda
orbit at a common digest. Separately, two signatures sharing four distinct
keys cannot have a nontrivial endomorphism hop between their verification
points at even one common key. These results do not exclude every graph,
three-common-key subsets across different signatures, or other predicates.

Evidence: `locally-reproduced`; deployment: `unclassified`. The
[Python](r14_orbit_binding.py) and [JSON](r14_orbit_binding.json) contain two
polynomial certificates, two independent matrix certificates, eight point
formula vectors and eight four-root transport vectors. No valid Script
candidate, Core execution or covenant is supplied. These are algebraic
templates, so there are no measured script/witness/hint/stack costs for a
new primitive.

## One signature under an affine orbit of keys

Take three distinct finite keys

```
K0=A+B,    K1=A+lambda*B,    K2=A+lambda^2*B,
```

with B nonzero. Suppose the same valid numerical signature `(r,s)` and
same native digest z verifies under all three. Its verification points are

```
Ui=(zG+rKi)/s = D+lambda^i*E.
```

They are distinct and satisfy `U0+lambda*U1+lambda^2*U2=0`. Every Ui lies
in the recovery set consisting of the available points at x=r and x=r+n,
with both signs. Any three distinct points of that set include an
antipodal pair. Substituting that pair into the weighted identity forces
the third point to be

```
Y = ±(lambda-lambda^2)*X
```

for a point X from the pair. Consequently X and Y must occupy the two
different x lifts of the same r; their ordinary coordinate difference is
either +n or -n.

Let `delta=lambda-lambda^2`, so `delta^2=-3 mod n`. Because
`delta*X=phi(X)-phi^2(X)`, the ordinary addition law gives the rational
coordinate identity

```
x(delta*X) = -(x(X)^3+28)/(3*x(X)^2) mod p.
```

The denominator is nonzero: x=0 does not lift to secp256k1. The required
coordinate difference therefore implies, for one sign epsilon,

```
4*x^3 + epsilon*3*n*x^2 + 28 = 0 mod p.
```

For both epsilon=-1 and epsilon=+1, exact polynomial calculation yields
`gcd(F, X^p-X)=1`. Neither cubic has any root in Fp, even before restricting
to the intervals where the two r representatives are possible.

The separate matrix check builds multiplication by X in the three-dimensional
algebra `Fp[X]/F`. Its matrix `M^p-M` has rank three for each cubic. Thus
its kernel has dimension zero, independently certifying that the gcd degree
and field-root count are zero without invoking the polynomial gcd routine.
All coefficients, remainders, matrices and reduced echelon forms are stored.
Eight full-size point vectors also verify the rational coordinate formula,
including both representatives for r=2 and r=4.

This template therefore cannot supply a successful signature witness. If
the three keys are freely supplied and their affine relationship is not
checked, the premise disappears; one cannot then claim an enforced orbit.

## Four common keys across different signatures

A denser tetrahedral graph can assign one signature to each perfect matching
of four keys. Each signature then verifies under all four distinct keys.
Let two such signatures have parameters `(ri,si,zi)` and `(rj,sj,zj)`.
Since a recovery set has at most four points, each signature's four
verification points are its complete set, with point sum zero.

At every common key, eliminating that key gives the same affine map

```
Uj = a*Ui + b*G,
a = rj*si/(sj*ri),
b = (zj-rj*zi/ri)/sj.
```

Summing over the four keys yields `0=4*b*G`, hence b=0 since n is odd.
This center argument is essential: an endomorphism hop at a single key
would not imply a pure endomorphism map if an unknown offset remained.

Now suppose at one common key the nonzero verification points obey
`Uj=epsilon*lambda^k*Ui`, with k=1 or 2 and epsilon=+1 or -1. Since b=0,
the prime-order group forces `a=epsilon*lambda^k`. The entire four-point
recovery set would therefore be transported by this same map.

Its two distinct x coordinates originally differ by n. After transport
they differ by `beta^k*n mod p`. To remain a four-point ECDSA recovery set,
the transformed coordinates must instead differ by +n or -n in Fp. That
would require `beta^k=+1` or `-1`, neither of which holds. The sign epsilon
does not affect x. This proves the contradiction for every four-root r,
not just the eight transport examples stored in the JSON.

## Remaining constructive boundary

Four common keys force the complete recovery sets and remove the affine
offset. Three common keys leave subsets and may pair their antipodal points
differently. The above transport proof must not be applied to that case
without additional work. Likewise, R13's shared two-key interface does have
valid public witnesses; its defect is the missing orbit predicate, not this
four-key obstruction.

Only the variant where every orbit r is small enough for a 32-byte hash
signature is exhausted by the separate
[unique-coordinate-orbit enumeration](r14_orbit_observable.md). A construction
with one hash signature and other full-length signatures remains outside
that enumeration and needs its own native relation and work analysis.
