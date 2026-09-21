# R17: the correlated raw-DER diagonal and its exceptional scalar family

Question: let alpha be the actual 32-byte native ALL hash, also interpreted
as positive canonical `DER(r,s)||flag`. Can alpha verify at the constant
SINGLE-bug digest C while a second signature beta verifies at numerical
digest `z=int(alpha)`, with three distinct common keys?

The diagonal has a precise exceptional case absent from R16's independent
answer model. For fixed r, layout and mixed source midpoint, a necessary
equation usually fixes at most one s for each candidate target r. When two
coefficients vanish, it instead holds for every admissible s. A conditional
construction for that whole family is given below, including the still
required third-key geometry. An exact scan excludes the exceptional family
for every positive r with one or two DER bytes and all 256 flags. No positive
secp256k1 diagonal witness or Bitcoin covenant is obtained.

Evidence: `locally-reproduced`; deployment: `unclassified`.
[Python](r17_correlated_diagonal.py) and [JSON](r17_correlated_diagonal.json)
contain 918 exact byte-layout checks, exhaustive scalar-identity checks, and
8,388,352 bounded secp256k1 integer cases. No point-log randomness is assumed.
There is no hash-to-scalar projection, chosen hash output, synthetic hash
preimage, new Script, witness, Core run or field-library test. Script bytes,
witness bytes, hint/data items and stack/opcode metrics are not applicable.

## Exact raw bytes and the five centers

Use `C=2^248`, the big-endian scalar of the actual legacy SINGLE-bug bytes
`01` followed by 31 zero bytes. The source flag must select that constant
in the executing context; the scan grants all flags as a superset. The
ordinary legacy SINGLE flag bytes have `(flag & 31)==3`, including the
ANYONECANPAY choices and otherwise ignored upper bits.

As in [R7's variable-DER derivation](r7_variable_der.md), if r and s have
nr and ns DER bytes, then `nr+ns=25` and

```
z = int_big_endian(alpha) = Z0 + 256*s,
Z0 = D + A*r,
A = 2^(8*(ns+3)).
```

D depends only on the layout and flag. Both Z0 and z are strictly between
zero and n: the 32-byte word starts `30 1d`, and subtracting its s bytes
leaves positive fixed syntax. Thus z is its actual integer value, without
mod-n wrap or a zero-digest branch. Canonical positive s is also less than n.

Three distinct common finite keys require four source and four target nonce
roots. Hence `r,rho` both lie in `[1,Delta-1]`, where `Delta=p-n` and rho is
beta's r. The source four-root set is `{A0,-A0,B0,-B0}`. Every target triple
contains an antipodal pair. Its preimages are either a source antipodal
pair, whose midpoint is V=O, or one of the four mixed midpoints V. Write
`V=vG` abstractly; knowing v is not an algorithmic assumption.

[R16's five-center identity](r16_three_key_support.md) gives

```
rho*(C-s*v) = r*z = r*(Z0+256*s),
s*(256*r+rho*v) = C*rho-r*Z0.                (1)
```

The matched center is v=0 and yields the advertised
`rho=z*r/C mod n`. For each fixed rho it has the unique candidate
`s=(C*rho-r*Z0)/(256*r)`. Its coefficient cannot vanish. The result does
not assert that this candidate has the required byte length or that three
common keys actually exist.

For a mixed midpoint, equation (1) can instead be tested as the public
group equation

```
s*(256*r*G+rho*V) = (C*rho-r*Z0)*G.          (2)
```

The group point and right scalar are computable from r, rho and the lifted
source roots. Solving for s can still require a bounded discrete logarithm.
Writing (1) with an abstract v does not provide that logarithm.

## The exceptional case is an actual diagonal degeneracy

For fixed r, rho and V, equation (1) has one scalar solution if its left
coefficient is nonzero, no solution if only the left coefficient vanishes,
or every scalar solution if both sides vanish. Since Z0 is nonzero, the
last case is exactly

```
rho = r*Z0/C mod n,
v   = -256*C/Z0 mod n.                       (3)
```

This is a mixed-center condition: v cannot be zero. Crucially it is publicly
checkable without computing any source logarithm:

```
1 <= rho < Delta,
Z0*V + 256*C*G = O.                          (4)
```

The canonical s interval contains no pole `C-s*v=0`, because under (3) a
pole would also imply `Z0+256*s=0 mod n`, whereas the actual DER z lies
strictly between zero and n. Therefore the pair-center equation really does
hold for every canonical s in that layout if (3) holds.

This is only a necessary pair-center family. A precise sufficient geometric
addition makes it a three-common-key family. Let a source triple be
`(A0,-A0,B0)`, with `V=(A0+B0)/2`. Require a fixed nonzero public scalar q
for which the three points

```
T_U = ((rho/r)*U + 256*G)/q,
U in (A0,-A0,B0),                            (5)
```

are three distinct finite recovery roots at target r=rho. Under (3),
`T_B0=-T_A0`; the third root requirement in (5) is an additional check.
Then for each canonical source s set `beta_s=q*s mod n`. For every point
in the triple,

```
(beta_s*T_U-z*G)/rho
  = ((rho*s/r)*U+256*s*G-(Z0+256*s)*G)/rho
  = (s*U-C*G)/r.
```

Discard any s producing an infinity common key. The affine maps preserve
distinctness of the three remaining keys. beta_s is nonzero; if LOW_S is
needed, negate it when necessary and negate its recovery roots, preserving
the recovered key set. beta need not be 32 bytes. Only source alpha has the
raw32-byte requirement. Finding q can require a discrete logarithm; (5)
does not grant its cheap availability.

Equations (3)--(5) are a falsifiable conditional family, not a found one.
Even a geometrically successful family consists of acceptable raw byte
strings. An actual native transaction still must hash to a member, and its
key/hash/output relations must be enforced by Script.

## Complete bounded exclusion using the real 32-byte layout

The first predicate in (4) can be checked before any curve lifting:

```
rho = r*(D+A*r)/C mod n < Delta.
```

The program enumerates all r in `[1,32767]` using their actual minimal DER
length and all flags0..255. Changing the flag by one increments D by one;
the recurrence `rho(f+1)=rho(f)+r/C mod n` therefore visits every case.
It is independently compared with direct modular evaluation at both flag
endpoints for every r. No candidate has rho below Delta.

| r DER bytes | s DER bytes | Complete r range | Flag/r cases | Small-rho hits | Minimum rho, log2 |
|---:|---:|---|---:|---:|---:|
| 1 | 24 | 1..127 | 32,512 | 0 | 240.1301109 |
| 2 | 23 | 128..32767 | 8,355,840 | 0 | 234.8164013 |

Since rho for the exceptional family is independent of s, the rejection
covers the entire canonical s interval in each listed layout, rather than
sampled s values. It excludes neither the ordinary one-s branch nor any
larger r. The JSON records the exact minimum residues and their r/flag
arguments. The total is 8,388,352 combinations, with zero exceptional hits.

Separately, every scalar solution set of (1) is compared with its linear
classification for prime moduli5,7,11, fixed nonzero C, all nonzero r and
rho, and every Z0,v,s. The 14,264 configurations include 152 all-s cases,
12,832 single-s cases and 1,280 empty cases. These are complete scalar
identity checks, not toy replacements for a raw SHA256 hash or a positive
elliptic-curve construction. The byte checks use actual canonical 32-byte
DER strings and cover the boundaries of every nonempty r-width layout.

## What can be counted without random point-log assumptions

For fixed r and mixed V, equation `Z0*V=-256*C*G` permits at most one flag
across all 256 choices. V is nonzero, the prime-order map is injective, and
changing the flag changes Z0 by that small integer without modular aliasing.
There are at most four mixed V points per r. Consequently the exceptional
branch has at most

```
sum_r 4*|I_s(r)| / 2^256
 = (4/256)*p_source_r_below_Delta
 ≈ 2^-52.01110165
```

of all32-byte strings. This grants every midpoint, omits the small-rho and
third-key tests, and even retains the low-r cases excluded above. It is a
deterministic accepted-string upper bound for this exceptional branch, not
a measured density, a randomness claim about v, or a useful universal
work lower bound. Under an explicitly ideal uniform native-hash model it
also bounds one query's chance of entering this branch. It says nothing
similar about the ordinary branch without additional analysis.

For a fixed nonexceptional r and V, the fractional map
`rho=r*(Z0+256*s)/(C-s*v)` is injective away from its pole. This yields the
elementary cap `min(|I_s|,Delta-1)` on s values satisfying its necessary
small-rho condition, but does not supply their locations or prove a search
exponent. No equidistribution of this deterministic map is asserted.

## Remaining constructive obligation

The honest equality alpha=the native hash need not require matching an
independently preselected target: a candidate may derive the same digest
bytes in Script from a supplied actual sighash preimage. Native source
binding and authentication of the intended outputs must still be established
for that concrete Script. The R16 independent-answer query bound cannot be
applied to this diagonal, and this report does not apply it.

The next exact test for the exceptional route is to supply an r above32767,
its four source roots, actual layout/flag, and rho satisfying (3)--(4), then
a charged procedure for q satisfying (5). Finally provide an actual funded
transaction whose native ALL hash lies in the resulting raw32-byte family,
with its Script checks and total search costs. For the ordinary route,
equation (2) retains the unknown-log and third-key obligations. Neither
route has yet supplied a complete Bitcoin-scale witness.
