# R18: complete three-root test for six endomorphism slopes and all translations

Question: can an affine map `U -> a*U+b*G`, with
`a in {+/-1,+/-lambda,+/-lambda^2}` and arbitrary nonzero b, map three
distinct secp256k1 ECDSA recovery roots to three recovery roots at another r?
Comparison objective: close R15's arbitrary-translation loophole for these
six efficiently available slopes, without sampling translations.

**No such map exists on secp256k1.** The necessary coordinate system has
twelve finite-field resultants of degree at most 80. Their field-root sets
contain 29 roots in aggregate, and none lies in its required source
integer interval. This covers all translations and source r for the stated
six slopes. It is not an exclusion of arbitrary scalar slopes or a general
covenant impossibility.

Evidence: `locally-reproduced`; deployment: `unclassified`.
[Python](r18_endomorphism_resultant.py) and
[JSON](r18_endomorphism_resultant.json) record the exact interpolated
polynomials, determinant samples, Frobenius remainders, linear factors and
all field roots. There is no Script, witness, hash-preimage search, Core
execution or library field test; script/witness/stack metrics do not apply.
The [independent audit](r18_resultant_audit.md) checks the elimination using
separate arithmetic and small-curve enumeration.

## Relabeling every nonzero-translation case

Write `phi(x,y)=(beta*x mod p,y)=lambda*U`. Three distinct roots require
both ECDSA x branches, so a source triple can be labeled `(A,-A,B)` with
`x(B)-x(A)=d`, where the ordinary integer d is +n or -n. Similarly the
target triple contains exactly one antipodal pair and one root on its
other x branch. All points are finite and their ECDSA r values are nonzero.

A nonzero translation cannot send the source antipodal pair to the target
antipodal pair: adding their images would give `2bG=O`. Thus, after choosing
the sign of A, the target antipodal pair comes from A and B. For slope
`a=lambda^k`, its required translation is `-a*(A+B)/2`. Set

```
Cpt = (A-B)/2,
Dpt = -(3A+B)/2 = Cpt-2A.
```

The target triple is `phi^k(Cpt,-Cpt,Dpt)`. Also `B=A-2Cpt`.
A negative slope negates this triple and does not change its x coordinates,
so the same coordinate enumeration covers all six slopes.

Let `x=x(A)`, `y=x(Cpt)`. The two ordinary target x values differ by +n or
-n. Before applying phi, this gives the field difference

```
x(B) = x+d,                d=+/-n mod p,
x(Dpt) = y+e mod p,        e=(+/-n)*beta^(-k) mod p.
```

There are exactly three k values and two signs for each gap: twelve cases.
Passing these field equations alone would not suffice; the actual integer
branch conditions and point equations are separate final filters.

## Eliminate the two x coordinates

For points with distinct x coordinates u,v, both x(P+Q) and x(P-Q) satisfy

```
K(u,v,w) = (u-v)^2*w^2
           -2*(u*v*(u+v)+14)*w
           +(u*v)^2-28*(u+v) = 0.
```

The duplication function on `y_curve^2=x_curve^3+7` is

```
F(t) = (t^4-56*t)/(4*(t^3+7)).
```

Because `A-B=2Cpt` and `Cpt-Dpt=2A`, every proposed transport satisfies

```
K(x,x+d,F(y)) = 0,
K(y,y+e,F(x)) = 0.
```

Clearing the duplication denominators yields f(x,y) of bidegree at most
(4,8) and g(x,y) of bidegree at most (8,4). These denominators cannot vanish
at a finite point in the odd prime-order secp256k1 group: that would require
a point with y_curve=0. Clearing them may introduce extraneous roots, which
cannot invalidate a necessary-condition exclusion. The source x difference
d is nonzero in the field.

The resultant `R(x)=Res_y(f,g)` has degree at most
`4*4+8*8=80`. Every common finite root must give R(x)=0. This includes
specialized leading-coefficient degeneracies: the fixed-degree Sylvester
matrix is used rather than silently dropping a coefficient at a sample.

## Exact certificate construction

For each case the program evaluates the 12-by-12 Sylvester determinant at
x=0..80, using arithmetic modulo the secp256k1 field prime. Finite differences
interpolate the unique polynomial of degree at most 80. This is complete
because of the proved degree bound and because 81 is less than p. Six
additional determinant evaluations check the reconstruction, including
points near n and p; they supplement, rather than replace, the degree proof.

It then computes

```
L(x) = gcd(R(x), x^p-x)
```

and factors this squarefree product of all linear factors. Multiplication
of the recovered `(x-root)` factors must reconstruct L exactly. Splitting
has an explicit deterministic cap and raises an error if it cannot finish;
no unresolved factor is silently omitted.

| k | Source gap | Target gap | Resultant degree | Field roots | Source-branch roots |
|---:|---:|---:|---:|---:|---:|
| 0 | -n | -n | 75 | 2 | 0 |
| 0 | -n | +n | 74 | 3 | 0 |
| 0 | +n | -n | 74 | 3 | 0 |
| 0 | +n | +n | 75 | 9 | 0 |
| 1 | -n | -n | 75 | 1 | 0 |
| 1 | -n | +n | 75 | 0 | 0 |
| 1 | +n | -n | 75 | 1 | 0 |
| 1 | +n | +n | 75 | 4 | 0 |
| 2 | -n | -n | 75 | 1 | 0 |
| 2 | -n | +n | 75 | 1 | 0 |
| 2 | +n | -n | 75 | 0 | 0 |
| 2 | +n | +n | 75 | 4 | 0 |

For source gap +n, the allowed x interval is `[1,p-n-1]`; for gap -n it is
`[n+1,p-1]`. Every listed root is outside its interval. Consequently none
reaches the later target-coordinate, point-lifting or actual group-equation
filters. Six additional full-size point vectors directly verify both K
equations and the duplication identity before any interval restrictions.

## Consequences for R17, and limits

The zero-translation case is separate. Three roots include both source x
branches. Multiplication by lambda or lambda squared changes their gap to
`beta^k*n`, which is neither +n nor -n modulo p, as already checked in R14.
For slopes +/-1 and zero translation, the recovery root set is unchanged,
so the two numerical r values agree. In the constant/native three-key
interface its zero-center equation then forces `z=C`.

R17's raw32-byte DER diagonal has `z` beginning with bytes `30 1d`, whereas
the SINGLE constant begins `01 00`. Thus it cannot use that trivial z=C
case. If the conditional R17 family exists, its induced slope
`a=rho/(r*q)` must lie outside all six endomorphism scalars. Choosing
`q=+/-(rho/r)*lambda^(-k)` cannot close its third-key condition.

This does not exclude R17's general q, other small known scalar slopes,
or any construction using a different interface. The result removes a
specific complete family that previously had only sampled translations;
it does not supply the missing output binding or an honest-work algorithm.

Reproduce: `python3 research/covenant-2026-09-17/continuation/r18_endomorphism_resultant.py`.
