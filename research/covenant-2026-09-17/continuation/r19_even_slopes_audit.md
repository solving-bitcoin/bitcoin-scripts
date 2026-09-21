# R19: independent audit of doubled endomorphism slopes

Date: 2026-09-17. Question: does the finite polynomial test cover every affine
three-recovery-root transport with slope `±2*lambda^k`, `k=0,1,2`, including
zero translation and exceptional addition denominators?

**All formulas and all 27 full-size certificates passed the independent
audit.** No secp256k1 candidate reaches the exact source-coordinate branches.
The result is restricted to the stated six slopes; it is not an exclusion of
arbitrary slopes or a complete covenant construction.

Artifacts: [Python](r19_even_slopes_audit.py), [JSON](r19_even_slopes_audit.json),
and the audited [construction](r19_even_slopes.py).
Evidence `locally-reproduced`, deployment `unclassified`. The audit reuses only
its own R18 polynomial arithmetic; it imports no construction polynomial,
curve or root routines. There is no Script, Core or library field test.

## Independent derivation of the tripling expressions

Set `f=x^3+7`, `T=x^4-56x`, and `U=4(x^3+7)`. Duplication gives
`x(2A)=T/U`. Differentiation, equivalently the invariant differential relation
for multiplication by two, gives

```
y(2A)/y(A) = (T' U - T U') / (2 U^2).
```

The audit constructs the tripling numerator by substituting these expressions
into point addition `A+2A`, rather than copying the expanded numerator:

```
psi = x U - T = 3x(x^3+28),
N3 = x T (x U + T) + 14 U^2 - f(T' U - T U').
```

The resulting polynomial equals
`x^9 - 672x^6 + 2352x^3 + 21952`, and the denominator is `psi^2`.
Differentiating `x(3A)=N3/psi^2` gives

```
Y = N3' psi - 2 N3 psi',
y(3A)/y(A) = Y / (3 psi^3).
```

The independent point implementation confirms both tripling coordinates,
the `x(A-B)` formula, and the `x(3A+B)` formula against actual group addition.
The sign of the mixed `y(A)y(B)` term is positive for `A-B` and negative for
`3A+B`, as used by the construction.

For `b=x+d`, `t=y(A)y(B)` and `Q=b*psi^2-N3`, clearing the equation
`x(3A+B)-x(A-B)=e` produces the stated `L0+L1*t=0`.
The independent polynomial composition exactly matches every stored L0 and
L1 coefficient. Its degree bounds are `deg L0 <= 21`, `deg L1 <= 18`, so

```
H = L0^2 - L1^2*(x^3+7)*((x+d)^3+7)
```

has degree at most 42. All twelve concrete H polynomials have degree 39.
The audit additionally verifies exact divisibility by `Q^2` in every case;
this does not justify discarding the separately checked Q=0 branch.

## Exceptional denominators are covered

`psi=0` is the tripling denominator. A finite point with this denominator
would have `3A=O`, incompatible with secp256k1's prime group order. The
independent certificate also explicitly finds all four field roots of psi
and checks that none lifts to a curve point.

`Q=0` means `x(B)=x(3A)`, hence `B=3A` or `B=-3A` for finite points:

* For `B=-3A`, the target point `3A+B` is infinite, so the proposed recovery
  triple is invalid.
* For `B=3A`, the target coordinates are `x(2A)` and `x(6A)`. This is a
  legitimate exceptional branch and must be checked with the actual group
  relation. Clearing denominators loses the target-gap condition here.

There are six full-size point controls for each exceptional sign. For every
`B=3A` control, the audit deliberately changes e after constructing the real
point pair: **both H=0 and L0+L1*t=0 remain true**, while the actual target gap
is different. This directly confirms why a polynomial-only acceptance test
would be incomplete at Q=0.

The construction handles the branch independently. Both degree-nine Q
polynomials have complete certificates; one has no field roots, and the
other has three. None belongs to its required exact source interval. Thus
no exceptional secp256k1 candidate is lost by the final conclusion.

## Zero translation and complete root certificates

With zero translation, the source antipodal pair stays antipodal. The other
target coordinate is constrained by

```
x(2B)-x(2A)=e,
Z = T(x+d)U(x) - T(x)U(x+d) - e U(x)U(x+d).
```

The audit forms `T(x+d)` and `U(x+d)` by generic polynomial substitution,
independently of the construction's binomial-shift implementation. Each
result agrees coefficient-for-coefficient with the stored Z polynomial.
Their degrees are six, within the bound seven.

For all **27 certificates** — twelve H, twelve Z, two Q and one psi — the
audit independently recomputes `X^p mod polynomial`, the Frobenius remainder,
and its monic gcd with the polynomial. Multiplying `(X-root)` over each
stored list of distinct roots exactly reconstructs that gcd. Consequently
no field roots are missing from the lists.

Across the twelve translation cases H has **30 field roots** in aggregate;
the twelve zero-translation cases have **22**. All fail the exact source
condition for the indicated sign:

```
0 < x < p,
0 < x + sign*n < p,
0 < x mod n < p-n,
x mod n = (x + sign*n) mod n.
```

The independent implementation also contains the complete subsequent
lifting and group filters for any roots reaching that stage. In these
full-size cases none reaches it. The source/target signs, exponents, d/e
parameters, polynomial coefficients and empty filtered lists all agree
with the construction's report.

## Positive and negative point controls

There are 24 full-size controls: twelve ordinary additions, six `B=3A`
cases and six `B=-3A` cases. Four complete small prime-order groups provide
another 176 point-formula controls and an exhaustive scan of all source
triples, six doubled-endomorphism slopes, and every translation including
zero.

| Field p | Group order n | Affine maps tested | Valid three-root maps |
|---:|---:|---:|---:|
| 43 | 31 | 744 | 4 |
| 79 | 67 | 3,216 | 0 |
| 163 | 139 | 13,344 | 0 |
| 211 | 199 | 9,552 | 0 |

All **26,856** maps are checked by direct group scalar enumeration. The four
positive cases on p=43 use nonzero translations and slopes 12 or 19, which
are doubled endomorphism slopes on that curve. Each has source and target
r=7 and satisfies the proposed H and linear-t equations. These controls
ensure the reduction is tested on actual three-root transports as well as
negative cases.

No honest covenant work bound, output enforcement, native hash witness or
funding construction follows from this audit. Script bytes, witness items,
hint counts, opcodes and stack peaks are inapplicable to these host-only
mathematical checks.

Reproduce with:

```sh
python3 research/covenant-2026-09-17/continuation/r19_even_slopes_audit.py
```
