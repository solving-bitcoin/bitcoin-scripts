# R18: independent audit of translated endomorphism elimination

Date: 2026-09-17. Question: does the R18 resultant computation cover every
nonzero affine translation with slope `±lambda^k`, `k = 0,1,2`, carrying a
three-element ECDSA recovery-root subset into another such subset?

**The reduction and all twelve secp256k1 cases passed this independent audit.**
There are no candidates in the actual source coordinate branches for this
slope class. This is an exact finite algebraic result about those six slopes;
it is not an arbitrary-slope exclusion, a complete covenant, or a Core result.

Artifacts: [independent Python](r18_resultant_audit.py),
[JSON](r18_resultant_audit.json), and the audited
[construction](r18_endomorphism_resultant.py).
Evidence `locally-reproduced`, deployment `unclassified`. No construction
curve, polynomial or resultant functions are imported by the audit.

## Classification and coordinate equations

Write the source triple as `(A, -A, B)` and its affine image as `aQ + Z`,
with `a = ±lambda^k` and `Z != O`. The image of the source antipodal pair
sums to `2Z != O`, since the curve group has odd prime order. Consequently
the target's antipodal pair uses `B` and one member of the source pair;
choose that member's label to be `A`.

The required translation is then `Z = -a(A+B)/2`, and the target triple is

```
aC, aD, -aC,
C = (A-B)/2,
D = C-2A = (-3A-B)/2.
```

These labels cover either target-pair orientation. The sign in `±lambda^k`
does not affect x-coordinates. Because three distinct recovery roots require
both x-coordinate branches, with `p < 2n`, we have

```
xB = xA + d,                     d = ±n as an integer,
xD = xC + e modulo p,            e = ±n / beta^k modulo p.
```

For points on `y^2 = x^3+7`, define

```
K(u,v,w) = (u-v)^2 w^2 - 2[uv(u+v)+14]w
           + (uv)^2 - 28(u+v),
F(t) = (t^4-56t) / [4(t^3+7)].
```

`K` is the biquadratic relation for the x-coordinate of a point sum or
difference; `F(t)` is the duplication x-coordinate. The point equalities
`2C=A-B` and `2A=C-D` therefore imply, for `x=xA`, `y=xC`,

```
K(x,x+d,F(y)) = 0,
K(y,y+e,F(x)) = 0.
```

The audit checked the stated coefficients by composing these formulas
through generic polynomial operations, separately from the construction's
expanded coefficient formulas. It also checked direct numerical evaluation
of the original rational formulas. The denominators cannot vanish for a
finite secp256k1 point: a zero denominator would give y-coordinate zero,
hence nontrivial order two, incompatible with the group order.

## Resultant degree and independent computation

After clearing denominators, the two polynomials have bidegrees at most
`(4,8)` and `(8,4)` in `(x,y)`. The resultant in y therefore has degree in x
at most

```
4*4 + 8*8 = 80.
```

The 12 by 12 Sylvester determinant contains four coefficient rows from the
first polynomial and eight from the second, which gives the same bound.
Thus 81 distinct evaluation points determine the resultant over the field.
The construction's 81-point interpolation is sufficient; its observed
resultant degrees are 74 or 75.

The independent audit uses **polynomial Euclidean remainders**, with the
identity

```
Res(f,g) = (-1)^(deg(f)*deg(g))
           * lc(g)^(deg(f)-deg(f mod g)) * Res(g,f mod g).
```

It does not build Sylvester matrices or interpolate. It evaluates the
construction's stored polynomial at every x from 0 through 80, plus extra
small, large and SHA256-derived deterministic points and all listed field
roots. **All 1,169 independent resultant evaluations match.** The audit also
checks **9,352 direct K evaluations** against the generic polynomial forms.
Given the degree bound, agreement at all 81 consecutive points establishes
identity with the independently evaluated resultant polynomial, not merely
agreement at a few selected points.

For every case, a separately implemented polynomial exponentiation and gcd
recomputes

```
gcd(resultant(X), X^p-X).
```

Each result matches the stored factor. Multiplying `(X-root)` over the
listed, distinct roots reproduces that monic gcd, so the field-root list is
complete. The 12 cases cover all three exponents and both source/target gap
signs; their gap parameters are independently checked. All 29 listed roots
fail the actual source branch condition

```
0 < x < p,
0 < x + sign*n < p,
0 < x mod n < p-n,
x mod n = (x + sign*n) mod n.
```

No point-lifting or target-root heuristic is needed after this failure.

## Complete small-curve controls

A fresh point addition implementation enumerates each entire small prime-order
curve and confirms that its scalar table equals the full affine point set.
It then enumerates every three-root subset, every nonzero scalar slope and
every nonzero translation. Endomorphism slopes are identified independently
from the coordinate action `(x,y) -> (beta*x,y)`.

| Field p | Order n | All nonzero-slope maps | Endomorphism-slope maps | Nonzero-translation endomorphism matches | Other-slope positive controls |
|---:|---:|---:|---:|---:|---:|
| 43 | 31 | 3,600 | 720 | 0 | 8 |
| 79 | 67 | 34,848 | 3,168 | 0 | 0 |
| 163 | 139 | 304,704 | 13,248 | 0 | 8 |
| 211 | 199 | 313,632 | 9,504 | 0 | 0 |

The **656,784** total maps include **26,640** maps in the audited six-slope
class. The 16 positive controls outside that class verify the relabeling,
point equations, duplication formula and both K equations on real translated
three-root matches. They also demonstrate why the conclusion must retain its
slope restriction. For an arbitrary slope the pulled-back target coordinate
gap need not equal `±n/beta^k`.

This is standalone host mathematics, not a repository field-arithmetic test.
There are no Script operands, hints, witnesses, script bytes, opcode or stack
metrics to report. No funding construction or honest-work estimate for a
complete covenant is implied.

Reproduce with:

```sh
python3 research/covenant-2026-09-17/continuation/r18_resultant_audit.py
```
