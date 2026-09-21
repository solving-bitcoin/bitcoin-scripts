# R19: complete transport test for doubled endomorphism slopes

Question: can an affine map with slope `a=+/-2*lambda^k`, k=0,1,2, carry
three distinct secp256k1 ECDSA recovery roots to three recovery roots?
Comparison objective: test the next simple computable slopes outside R18's
six endomorphisms, with every translation and all exceptional branches.

**No such map exists, including zero translation.** Twelve degree-39
polynomials cover nonzero translations, twelve degree-six polynomials cover
zero translation, and three separate denominator certificates cover the
exceptional branches. Every possible source-coordinate root fails its
required integer branch or curve-lifting condition.

Inverting an affine map gives the immediate further exclusion of slopes
`+/-lambda^k/2`. Thus twelve scalar slopes are excluded using six direct
slope calculations. This does not exclude arbitrary slopes, and it does
not imply the corresponding result for factors four or other multipliers.

Evidence: `locally-reproduced`; deployment: `unclassified`.
[Python](r19_even_slopes.py), [JSON](r19_even_slopes.json), and the
[independent audit](r19_even_slopes_audit.md) supply exact polynomial and
root certificates. No Script, witness, Core execution or library field
tests are involved; script/witness/stack/opcode metrics are inapplicable.
No complete covenant or honest-work bound follows from this result.

## Complete relabeling and point formulas

The source triple can be labeled `(A,-A,B)` with ordinary coordinate
gap `x(B)-x(A)=d`, d=+n or -n. With a nonzero translation the target
antipodal pair cannot come from `(A,-A)`, so it comes from `(A,B)` after
choosing A's sign. The translation for slope `2*lambda^k` is then
`-lambda^k*(A+B)`. Before applying the endomorphism, the target triple is

```
A-B, -(3A+B), B-A.
```

Therefore the two target x coordinates are those of `A-B` and `3A+B`,
scaled by beta^k. A negative slope negates all points and has the same x
test. Write `x=x(A)`, `b=x+d`, `t=y(A)*y(B)`. Then

```
t^2 = (x^3+7)*(b^3+7),
x(A-B) = [x*b*(x+b)+14+2*t]/d^2.
```

For tripling define

```
psi = 3*x*(x^3+28),
D3  = psi^2,
N3  = x^9-672*x^6+2352*x^3+21952,
Y   = N3'*psi-2*N3*psi'.
```

Here primes denote formal polynomial derivatives. The tripling formulas are
`x(3A)=N3/D3` and `y(3A)/y(A)=Y/(3*psi^3)`. Point addition then gives

```
Q = b*D3-N3,
x(3A+B) = [b*N3*(b*D3+N3)+14*D3^2-(2/3)*Y*psi*t]/Q^2.
```

All arithmetic in these formulas is over the secp256k1 field. Their
denominators are handled below; they are not silently assumed nonzero.

## A finite polynomial for every nonzero translation

Let `e=(+/-n)/beta^k mod p`. The necessary target gap is
`x(3A+B)-x(A-B)=e`. Away from exceptional denominators, multiplying out
gives `L0+L1*t=0`, where

```
M  = x*b*(x+b)+14,
L0 = d^2*[b*N3*(b*D3+N3)+14*D3^2]-(M+e*d^2)*Q^2,
L1 = -(2/3)*d^2*Y*psi-2*Q^2.
```

Eliminating t yields the necessary polynomial equation

```
H(x) = L0^2-L1^2*(x^3+7)*(b^3+7) = 0.
```

The bounds `deg L0<=21` and `deg L1<=18` give `deg H<=42`.
Every concrete H here has degree 39. The independent audit also finds
`Q^2` as an exact factor; keeping that factor cannot lose a candidate,
and Q=0 is treated independently rather than accepted from H alone.

For each H the program computes `gcd(H,X^p-X)`, splits every linear factor,
and verifies that the product over the listed roots reconstructs the gcd.
This yields a complete field-root list. The source interval is
`[1,p-n-1]` for d=+n and `[n+1,p-1]` for d=-n. None of the 30 field roots,
counted across the twelve cases, belongs to its required source interval.

## Exceptional denominators

The four field roots of psi do not lift to secp256k1 points. Equivalently,
a finite point with `3A=O` cannot occur in its prime-order group.

The other denominator Q requires more care. Q=0 means `B=+/-3A`:

- With `B=-3A`, the target point `3A+B` is infinite and cannot be a
  recovery root.
- With `B=3A`, the targets have x coordinates `x(2A)` and `x(6A)`.
  This is a real exceptional case, not an automatic failure. The cleared
  equations lose their target-gap constraint here.

The two degree-nine Q polynomials are therefore enumerated separately,
one for each source gap sign. They have zero and three field roots, and
none satisfies its source interval. No exceptional candidate remains.
The independent point controls explicitly demonstrate the danger of
skipping this branch: at B=3A both cleared equations can hold after e is
changed to an incorrect value. Direct group verification would then fail.

## Zero translation

With no translation, the source antipodal pair remains antipodal. Let

```
T(x)=x^4-56*x,        U(x)=4*(x^3+7).
```

The target gap before the endomorphism is `x(2B)-x(2A)=e`, so

```
Z(x) = T(x+d)*U(x)-T(x)*U(x+d)-e*U(x)*U(x+d) = 0.
```

Each concrete Z has degree six, within its degree-seven bound. Duplication
denominators cannot vanish for a finite point in this odd-order group.
The twelve complete root lists contain 22 roots in aggregate, all outside
their source intervals.

| k | Source gap | Target gap | H field roots | Z field roots | Source-branch roots |
|---:|---:|---:|---:|---:|---:|
| 0 | -n | -n | 3 | 1 | 0 |
| 0 | -n | +n | 0 | 1 | 0 |
| 0 | +n | -n | 8 | 1 | 0 |
| 0 | +n | +n | 3 | 1 | 0 |
| 1 | -n | -n | 0 | 0 | 0 |
| 1 | -n | +n | 1 | 3 | 0 |
| 1 | +n | -n | 3 | 3 | 0 |
| 1 | +n | +n | 4 | 0 | 0 |
| 2 | -n | -n | 1 | 2 | 0 |
| 2 | -n | +n | 0 | 4 | 0 |
| 2 | +n | -n | 4 | 4 | 0 |
| 2 | +n | +n | 3 | 2 | 0 |

## Independent reproduction and scope

The independent audit derives N3 by composing duplication with addition,
instead of copying its expanded coefficients. It separately rebuilds all
27 certificates, their Frobenius remainders/gcds and complete root lists.
It also checks 24 full-size point examples, 176 small-curve point examples,
and all 26,856 relevant affine maps on four small prime-order curves.
Four positive transported triples occur on the p=43 curve and satisfy
the proposed equations. The full-size exclusion is therefore not based on
a test suite that accepts no real positive examples.

The inverse-map corollary needs no distribution assumption. If a map
`P -> aP+B` carried one valid triple to another, its inverse would carry
the second triple back with slope `a^-1` and translation `-a^-1*B`.
Both source and target coordinate domains were fully covered. Since
`(2*lambda^k)^-1=lambda^(-k)/2`, the excluded inverse slopes are exactly
`+/-lambda^k/2`, k=0,1,2. Composing maps cannot extend this conclusion to
factor four without an additional proof that an intermediate triple is
itself a recovery triple.

For R17's conditional signature family, the induced slope
`a=rho/(r*q)` must avoid these twelve scalars as well as R18's six.
General q, another source/native interface, and mandatory output-reference
verification remain open. Further work should supply a constructive
mechanism for one of those obligations, rather than treat this finite
exclusion as a general impossibility theorem.

Reproduce: `python3 research/covenant-2026-09-17/continuation/r19_even_slopes.py`.
