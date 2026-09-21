# R9: independent certificate for three-key ECDSA digest equality

Date: 2026-09-17. Question: can the r+n branch permit three distinct common
recovery keys for one valid ECDSA signature on two different digest scalars?

**No such exception exists on secp256k1.** Three distinct group public keys
that all verify the same valid ECDSA signature on each of two digests force
those digests equal modulo the curve order n. The result includes every
possible r and s, both nonce signs, and the second possible x coordinate.
It does not turn a native digest into a readable Script number or provide
an independently authenticated intended-output context.

Evidence for this independent exact arithmetic audit is `locally-reproduced`,
deployment `unclassified`. No Script, Bitcoin Core or repository field tests
are executed here. The proof's complete polynomial certificate is checked
using a different algorithm from the originating experiment.

## Why only a tripling exception could matter

For a valid shared signature (r,s), write its nonce-point set as S. For a
digest scalar z, its recovery public keys are

```
K(z) = { (sR-zG)/r : R in S }.
```

Because r and s are nonzero, the mapping is injective. With at most two
nonce roots there cannot be three distinct common keys. With four roots,
`S={A,-A,B,-B}`, where the two x coordinates are r and r+n. Three common keys
for z1 and z2 imply `|S intersect (S+t)| >= 3`, with
`t=(z2-z1)/s * G`.

Suppose t is nonzero. Translation by t has no cycle of length at most four
in a group of prime order n>4. The induced directed graph on the four points
therefore consists of disjoint paths. Three edges on four vertices require
one four-vertex path, so `S={a,a+t,a+2t,a+3t}`. Since S is symmetric, its sum
is zero, giving `4a+6t=0`. Thus

```
S = { -3t/2, -t/2, t/2, 3t/2 }.
```

Consequently B must equal ±3A, or A must equal ±3B. The distinct coordinates
then require the exact integer relation `x(3P)=x(P)+n` or `x(P)-n`, not merely
an arbitrary field difference.

## Exact tripling polynomial

For y²=x³+7, ordinary doubling and addition give

```
x(3P)-x = -8(x³+7)(x⁶+140x³-392)/(3x⁴+84x)².
```

One direct derivation uses `x(2P)-x=-(3x⁴+84x)/(4y²)`. The slope from P to
2P is `(16y⁴-3x²(3x⁴+84x))/(2y(3x⁴+84x))`; substituting it into
`x(3P)=slope²-x(2P)-x` and reducing y²=x³+7 yields the displayed identity.
The denominator cannot vanish for a nonidentity point on this prime-order
curve, since that would make 3P the identity.

For sign epsilon in {+1,-1}, the necessary polynomial is

```
F_epsilon(X) = 8X⁹ + epsilon*9nX⁸ + 1176X⁶
              + epsilon*504nX⁵ + 4704X³
              + epsilon*7056nX² - 21952  mod p.
```

The + case only permits `1 <= x <= p-n-1`. The − case only permits
`n+1 <= x <= p-1`. Zero r is excluded by valid ECDSA. It is sufficient to
show there is no polynomial root in those intervals, even before asking
whether the candidate coordinate lifts to the curve.

## Independent complete root counting by matrices

The [originating computation](r9_four_roots.md) uses polynomial Frobenius
powering, a gcd with X^p-X, and deterministic splitting. This audit does not
import any of those polynomial routines. It independently expands the integer
numerator and denominator, then constructs the 9-by-9 multiplication-by-X
matrix M for the quotient algebra Fp[X]/(F_epsilon).

The kernel dimension of multiplication by X^p-X is
`deg gcd(F_epsilon,X^p-X)`. Since X^p-X has each field element once as a root,
this is exactly the number of distinct Fp roots of F_epsilon. Matrix
exponentiation and modular Gaussian elimination independently give:

| Polynomial | Rank of M^p-M | Exact number of field roots | Roots in eligible interval |
| --- | ---: | ---: | ---: |
| F+ | 6 | 3 | 0 |
| F− | 9 | 0 | 0 |

All three supplied roots of F+ are independently substituted into the
polynomial, are distinct, and lie above p-n-1. The rank certificate proves
there are no additional field roots. F− has none anywhere in Fp. The first
column of M^p-M also agrees exactly with the independently recorded
Frobenius remainder. Full matrices, reduced row-echelon matrices, roots and
interval endpoints are retained in [the JSON](r9_recovery_audit.json).

Thus the required four-point arithmetic progression does not occur. The
only translation giving three common recovery keys is zero, and hence
z1=z2 modulo n. This is an exact curve-specific statement; no hash-randomness
or discrete-log hardness assumption is needed for the equality implication.

The graph lemma is additionally checked on 1,394 symmetric-set/translation
pairs in small prime-order groups, including 62 nonzero overlaps of at least
three. Those small checks corroborate the written proof; they do not replace
the full-size polynomial certificate.

## Native application boundary

Script must ensure three **distinct group points**, not just different byte
strings. Successful ECDSA checks plus 33-byte key-length checks give canonical
compressed keys, for which byte inequality is sufficient. Permitting both
compressed and uncompressed representations without normalizing would make
a mere byte inequality inadequate.

The exact same signature item must be reused in both contexts. Each actual
context must use its real native digest; a freely supplied alleged digest
does not satisfy the theorem's premise. Equality modulo n also allows the
rare two-representative ambiguity for raw 256-bit hashes. Neither that
distinction nor the funding dependencies may be discarded in a covenant.

Reproduce with `python3 research/covenant-2026-09-17/continuation/r9_recovery_audit.py`.
The input artifact's SHA256 is recorded. The independent matrix method uses
ordinary Python integers and no additional algebra package.
