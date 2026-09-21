# R15: an exact quartic test for three common recovery keys

Date: 2026-09-17. Question: can three distinct common recovery keys across
different signatures enforce a genuine nontrivial nonce endomorphism hop,
with only one signature constrained to a 32-byte hash output?

**A complete finite test for the previously open pairing pattern is obtained;
no native C/ALL construction is obtained.** For fixed nonzero public scalars
a,b in the recovery-root relation `Uj=a Ui+bG`, the mismatched antipodal case
reduces to one quartic over the curve field, followed by exact integer-coordinate
and native-message checks. The translation is retained throughout.

Artifacts: [Python](r15_three_common_keys.py),
[JSON](r15_three_common_keys.json). Evidence `locally-reproduced`, deployment
`unclassified`. The test exhaustively agrees with an independent group-index
enumeration on three small prime-order curves. Sixteen specified secp256k1
translation cases are also checked, without extrapolating them to all
translations. No Script fragment, witness, Core validation, hash preimage,
native C/ALL candidate, or setup bound below 2^64 is supplied. Script and
witness metrics are therefore not applicable. No library or field-library
tests were run.

## Exact map and the two pairing cases

For signatures `(ri,si)` and `(rj,sj)` at digest scalars zi,zj, a common key K
gives

```
K = (si Ui-zi G)/ri = (sj Uj-zj G)/rj,
Uj = a Ui+bG,
a = rj si/(sj ri),
b = (zj-rj zi/ri)/sj.                   (1)
```

All scalar divisions here are modulo n. Valid signatures make a nonzero.
Three distinct keys produce three distinct nonce roots on each side. Thus
**each signature must have four possible roots**, with x coordinates r and
r+n; in particular both ri and rj must satisfy `0<r<p-n`. An unrestricted
second DER signature does not remove this necessary branch restriction.
No three-point coordinate-orbit hypothesis from R14 is used.

A three-element subset of `{A,-A,B,-B}` contains exactly one antipodal pair.
There are two cases:

* **Pair matched.** The complete source antipodal pair maps to the complete
  target pair. Their sums force `2bG=O`, hence b=0 in the odd prime-order
  group. If a is one of `±lambda, ±lambda²`, x coordinates are multiplied
  by the corresponding nontrivial cube root beta or beta². Both r branches
  would then require `beta^e n = ±n mod p`, implying `beta^e=±1`, impossible.
  The source triple necessarily uses both x branches, so the gap condition
  cannot be omitted.
* **Pair mismatched.** Relabel the source triple as `(A,-A,B)` so its images
  are `(C,D,-C)`. The source antipodal pair maps to a target pair member and
  the singleton. This relabeling covers either choice of source branch,
  either sign of its pair, and either singleton sign.

For the second case define

```
U=(A-B)/2,             V=(A+B)/2.
```

Equation (1) is equivalent to

```
A=V+U, B=V-U,
bG=-aV,
C=aU, D=-a(2V+U).                     (2)
```

In particular b is nonzero: V=O would make B=-A, contradicting the distinct
x branches. This case is an affine translation, not automatically a pure
endomorphism hop. The matched/mismatched classification is exhaustive for
three distinct nonce roots, not merely a selected sign configuration.

The related R14 certificates remain separate; see
[r14_orbit_binding.py](r14_orbit_binding.py) and
[r14_orbit_binding.json](r14_orbit_binding.json). This artifact does not
re-run the four-key transport analysis.

## Quartic for a fixed public translation

Given nonzero a,b, compute the public point

```
V=-(b/a)G=(v,w).
```

It is finite and nonzero. Its y coordinate w is nonzero because the group
has odd prime order and no nonidentity point of order two. Write U=(X,Y).
Ordinary addition on `y²=x³+7` gives

```
x(V+U)-x(V-U) = -4wY/(X-v)².
```

The two source branches require the exact integer difference
`x(A)-x(B)=delta`, where delta is either +n or -n. Therefore

```
Y = -delta (X-v)²/(4w),
n²(X-v)^4 -16w²(X³+7) = 0 mod p.       (3)
```

This is one quartic, shared by both signs of delta. It has at most four
distinct field roots. At X=v its value is `-16w^4`, nonzero, so the excluded
addition denominators introduce no missing candidate.

For each field root and each sign of delta, the implementation reconstructs
U, A, B, C and D and requires:

1. The exact **integer** source difference is delta. A field congruence alone
   can instead represent a small difference involving p-n and is insufficient.
2. The source r is nonzero and below p-n.
3. C,D are finite, their exact integer x difference is +n or -n, and the
   target r is nonzero and below p-n.
4. All three source/target points are distinct, and every affine relation
   `target=a*source+bG` holds.

Conversely any mismatched triple for these a,b gives V and U above and is
therefore recovered by this enumeration. Thus (3) plus those filters is a
complete finite test for fixed a,b, not a search over all source coordinates.
It uses at most eight reconstructed U candidates before filtering.

For secp256k1 the code takes `gcd(F,X^p-X)` and completely splits that
squarefree polynomial. Its degree and reconstructed root product certify
the returned root set. The reused factor splitter has a 256-trial cap: if
that cap were exhausted, it raises an error rather than reporting no roots.
All recorded cases finish within the cap. The mathematical finite test does
not depend on an unproved claim that this particular splitting cap always
succeeds.

## Independent finite checks and their limits

Three toy curves use ordinary Python integers and complete point enumeration.
An independent comparison enumerates every source three-root subset and
every nonzero a,b directly in cyclic group scalar indices; it does not use
the quartic or coordinate-difference formula to obtain the expected matches.

| Curve | Nonzero a,b pairs checked | Mismatched triple matches | b=0 matched triples |
| --- | ---: | ---: | ---: |
| p=43, n=31 | 900 | 8 | 8 |
| p=79, n=67 | 4356 | 0 | 16 |
| p=163, n=139 | 19044 | 8 | 48 |

Every returned triple matches the independent enumeration exactly. The
first and third curves include actual nonzero-translation cases rather than only
empty acceptance sets. Those examples and their points are in the JSON.

A separate root-authored [audit](r15_three_common_keys_audit.py), with
[stored results](r15_three_common_keys_audit.json), imports neither the
curve code nor the quartic solver. It exhausts 315,216 subset/map combinations
over F211/order199 and 306,912 over F163/order139. The latter reproduces all
48 matched and eight mismatched triples and checks the signed quartic on
each genuine mismatch; the former has 16 matched and no mismatched triples.
These counts include source subsets, unlike the a,b-pair counts above.

For secp256k1, the bounded examples take `a=±lambda,±lambda²` and
`V=vG` for v in `{1,2,7,19}`, setting b=-av. The quartics have respectively
2,1,0,4 distinct field roots for those four V values. All sixteen cases
fail the exact source integer-gap filter; none reaches a target candidate.
This does **not** establish that other translations fail, bound their
density, or bound the work of every public solver.

## The remaining native C/ALL and hash obligations

Finding a geometric triple is not sufficient. For an actual first signature
alpha with parsed ri,si and first native scalar C, a chosen a and target rj
would require

```
sj = rj si/(a ri),
b = (z_ALL-rj C/ri)/sj,
bG = -aV.                              (4)
```

Here z_ALL must be computed from the actual completed transaction, its
funding outpoint and scriptCode. It cannot be assigned to the algebraic
scalar that makes (4) true. For a 32-byte hash-derived alpha, its exact bytes
must also equal the actual specified hash output; freely choosing ri or si
does not meet that condition. LOW_S normalization must be accounted for by
negating the corresponding root map; the tests include both signs of the
endomorphism scalar.

There is an additional useful necessary condition for any asserted pure
nonce hop `Uj=t Ui`, with `t in {±lambda,±lambda²}`. Together with (1),

```
(t-a)Ui = bG.
```

If t=a this forces b=0, returning to the excluded pure matched-branch case.
If t differs from a, it exposes a **required public nonce scalar**
`k=b/(t-a)` with Ui=kG. This is not an efficient procedure for satisfying
a hash-chosen ri: the construction still must achieve
`x(kG) mod n = ri`, along with the other branch and actual-message checks.
Computing k after writing down a desired relation does not solve that
constraint. No known-log point with the needed hash-chosen coordinate is
assumed to exist cheaply.

Finally, choosing an endomorphism scalar in a host construction is not proof
that three common-key checks force that scalar for every accepted witness.
The native verifier would still need a sound reason excluding other a,b
matches or showing they obey the same intended output restriction. No such
enforcement is supplied by this geometric test alone.

A falsifiable next constructive target is therefore: produce one actual
32-byte hash-derived alpha and a concrete funded C/ALL transaction whose
distinct common keys satisfy (3), both exact branch filters and (4), with
all generation costs charged; then provide the native binding argument
against alternative a,b witnesses. No such complete candidate was found in
this bounded task. The quartic gives an exact test for proposed translations
and identifies what remains to be constructed without ignoring the offset.

Reproduce with:

```
python3 research/covenant-2026-09-17/continuation/r15_three_common_keys.py
```
