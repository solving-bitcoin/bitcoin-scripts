# R9: literal-scalar mixing of all four recovery roots

Date: 2026-09-17. Question: does the r+n recovery branch enable cheap native
arithmetic between literal signatures, without revealing r/s or knowing the
nonce logarithms, and thereby help bind an intended output reference?

The tested new candidate shares **two distinct witness keys between
`(r=2,s=1)` and `(r=2,s=2)`**, in potentially different native contexts. It
cannot accept: all 16 possible root-switch offsets are distinct, so at most
one key can be common. This exact failure persists for every second literal
s from 2 through 127. It is not a discrete-log assumption or a repetition of
the earlier full-four-key equality proof.

The same enumeration gives a useful smaller equality relation. A further
complete polynomial calculation generalizes it to **every valid ECDSA
signature on secp256k1: three distinct keys common to two native contexts
force their digest scalars to be equal**. The fourth key is unnecessary,
including every possible r+n exception. This is a computer-assisted algebraic
result, with exact root certificates below. It remains native digest equality,
without a reference evaluator or a cheap way to make different ALL contexts
satisfy it. No complete covenant was found.

The companion Python/JSON contain exact secp256k1 point calculations, ECDSA
equations and raw layout counts: `locally-reproduced`, deployment
`unclassified`. The all-r root computation was additionally compared with an
independent matrix certificate. That Python program invokes no Bitcoin Core,
repository Script executor/compiler, rare hash search or field-library tests.
Separate Core boundary results and their independent readback are described
in §7. No primitive metrics changed.

## 1. All roots and the proposed affine relation

Let

```
A = lift_x(2),                 B = lift_x(n+2),
S = {A,−A,B,−B}.
```

Both x-coordinates lift on secp256k1. The executable computes all four points,
checks their curve equations, and records canonical compressed encodings.
The public scalars r and s below are literal signature bytes, not separately
supplied hints. The two ALL signatures are

```
sigma_1 = 300602010202010101       # r=2, s=1, ALL
sigma_2 = 300602010202010201       # r=2, s=2, ALL.
```

For a fixed scalar digest z and literal s, the complete recovery-key set is

```
K_s(z) = { (sR−zG)/2 : R in S }.
```

This follows from ECDSA verification/recovery in
[SEC 1 v2.0, May 21, 2009, §§4.1.4–4.1.6](https://www.secg.org/sec1-v2.pdf).
It requires public point operations only, so individual signatures under
their recovered keys do not require any nonce or key discrete logarithm.

A key P common to `K_1(z1)` and `K_t(z2)` satisfies

```
2P = R1−z1G = tR2−z2G,
(z2−z1)G = tR2−R1.                         (1)
```

For any fixed digest pair the left side is one point. Consequently the
number of common keys equals the multiplicity of that point in the complete
16-entry multiset `{tR2−R1 : R1,R2 in S}`. This turns the proposed native
relation into a finite, exhaustively checkable point-set question. No branch
sign is guessed and the r+n roots are not discarded.

## 2. Two shared keys with t=2 are impossible

For t=2 all 16 point values in (1) are distinct and none is infinity. Hence
the two recovery sets have at most one common key for **every** z1,z2. A
script requiring two distinct common keys cannot succeed, regardless of how
the transaction, funding or hash search is chosen.

The fixture repeats that exact 16-point enumeration for every t=1,...,127,
the complete positive one-byte DER-s range. The result is:

| Second literal s=t | Distinct offsets | Maximum multiplicity | Zero offset |
| --- | ---: | ---: | ---: |
| 1 | 9 | 4 | multiplicity 4 |
| each of 2,...,127 | 16 | 1 | absent |
| n−1 | 9 | 4 | multiplicity 4 |

The n−1 case is included to check the sign symmetry: `−S=S`. It is a
high-S counterpart, and no LOW_S policy claim is attached to it. The
failure for 2,...,127 is a concrete finite result for these literals, not a
theorem for every 256-bit s or arbitrary r.

One explicit raw locking-predicate layout for t=2 does the following:

1. Checks both entry keys have exactly 33 bytes and unequal encodings.
2. Checks sigma_1 under both keys in the first context.
3. Executes CODESEPARATOR, then checks sigma_2 under both original keys.
4. Removes both keys and leaves true.

Valid native signatures plus 33-byte length restrict keys to canonical
compressed points, so byte inequality means distinct group keys. The raw
layout is **76 bytes, 23 counted non-push operations, 2 entry key data items,
0 hints, combined main-plus-alt-stack peak 5**, with empty altstack. All keys
coexist at entry; all signatures are literal script data. This layout fits
the numerical legacy resource bounds but its mathematical acceptance set is
empty. No Core execution or optimized library metric is claimed.

CODESEPARATOR and legacy FindAndDelete determine the actual z1,z2. Their
details cannot rescue this candidate: the proof already quantifies over
every pair of scalar digests, including equal ones. The literal ALL flags
also remove the variable-root NONE/SINGLE ambiguity for this specific test.

## 3. A cheaper equality corollary, with a precise limit

For t=1 the nonzero root differences are

```
±2A, ±2B                  each once,
±(A+B), ±(A−B)            each twice.
```

Zero occurs four times. These eight nonzero points are distinct on the
actual curve; the executable checks this rather than assuming it. Thus any
nonzero translation can make at most two recovery keys common. **Three
distinct common keys force z2=z1 modulo n.** Full-set exhaustion is not needed.

The corresponding three-key raw layout has three size checks, three
pairwise inequalities, three signature checks in each context, one
CODESEPARATOR and cleanup. It is **124 bytes, 42 counted non-push operations,
3 entry key data items, 0 hints and peak 6**. This improves the earlier
178-byte/65-opcode four-key construction. Its input pushes, serialized
witness, funding wrapper and transaction weight are excluded; it is an
inspected raw layout, not a compiled primitive or executed transaction.

The scalar equality still does not authenticate a stack representation of a
reference sighash. Making two distinct native ALL contexts share their hash
is itself an additional requirement. Choosing the same mathematical z in
host tests is not a solution to that requirement, and modulo-n equality is
not necessarily byte equality of 256-bit digests. This corollary is recorded
as a resource improvement, not as the main new covenant candidate.

## 4. Complete generalization to every ECDSA r

The previous section only enumerates r=2. This section covers all possible
four-root sets on the actual curve, using an exact degree-nine computation.
It does not scan a selection of r values.

### Translation overlap reduces to tripling

Let `S={±A,±B}` be four distinct points in the prime-order secp256k1 group.
Suppose a nonzero translation delta has at least three points of overlap.
Draw an edge `X -> X+delta` whenever both points lie in S. The graph has
indegree and outdegree at most one. It has no cycle because a nonzero delta
has order n>4. Three edges on four vertices therefore form one path, so S
is a four-term arithmetic progression.

The sum of S is zero. Centering that progression gives
`S={−3D,−D,D,3D}` for a nonzero D. Its two antipodal pairs imply either
`B=±3A` or `A=±3B`. Thus a nonzero three-point overlap requires the two
ECDSA x-lifts to be related by tripling.

For a four-root ECDSA set the field x-coordinates are r and r+n, where
`1<=r<=p−n−1`. Consequently one of these conditions must hold:

```
x(3P) = x(P)+n,     1 <= x(P) <= p−n−1,
x(3P) = x(P)−n,     n+1 <= x(P) <= p−1.             (2)
```

The secp256k1 field prime, prime group order and cofactor one are specified
in [SEC 2 v2.0, January 27, 2010, §2.4.1](https://www.secg.org/sec2-v2.pdf).
They exclude nontrivial points of order two or three, so all denominators
used in the following doubling/addition derivation are valid for the points
in question.

### Direct derivation of the tripling formula

Write `U=x^3+7=y^2`, `W=3x^4+84x`, and `D=x(2P)−x`. The usual affine
doubling formula gives `D=−W/(4U)`. The slope from P to 2P is
`−3x^2/(2y)−2y/D`. Squaring that slope and subtracting the x-coordinates gives

```
x(3P)−x = 9x^4/(4U) + 6x^2/D + 4U/D^2 − 3x − D
         = −24x^2 U/W + 64U^3/W^2
         = −8(x^3+7)(x^6+140x^3−392)/(3x^4+84x)^2.
```

The cancellations use the exact polynomial identities
`9x^4+W−12xU=0` and
`8U^2−3x^2W=−(x^6+140x^3−392)`. The executable checks both symbolically
over Fp, and separately checks the final rational formula on seven actual
secp256k1 points. The symbolic derivation, not the seven samples, establishes
the formula for every relevant point.

Clearing the denominator in (2) yields the two field polynomials

```
F_plus(X)  = 8X^9 + 9nX^8 + 1176X^6 + 504nX^5
                     + 4704X^3 + 7056nX^2 − 21952,
F_minus(X) = 8X^9 − 9nX^8 + 1176X^6 − 504nX^5
                     + 4704X^3 − 7056nX^2 − 21952.
```

### All field roots, with a completeness certificate

For each F, the executable computes
`h=gcd(F, X^p−X)` by exact integer arithmetic modulo p. Modular exponentiation
computes `X^p mod F`; no degree-p polynomial is materialized. Since X^p−X is
the product of all distinct field-linear factors, h contains **every Fp
root** of F exactly once. Deterministic quadratic-character splits factor h,
and multiplying all recovered `(X−root)` factors must reproduce h exactly.
The JSON records F, its Frobenius remainder, h, all roots and split choices.

| Polynomial | Degree of h | Number of field roots | Roots in required interval |
| --- | ---: | ---: | ---: |
| F_plus | 3 | 3 | 0 |
| F_minus | 0 | 0 | 0 |

The three F_plus roots are

```
0xcd88f2959f8ddf0e2e3b6839dd3d35c066ebf89fc1c7aff0a413d6bcdc345a3
0x83176ae2e992d9346bc7502fcae8be272cf9ce823cff90f821ec3db649c118fb
0xadd4ca93f5b9c23f9aa170369189d9100847ed4ea38f4b97f4e14fd9c52a3658
```

All exceed
`p−n−1 = 0x14551231950b75fc4402da1722fc9baed`.
F_minus has no field root at all, including the required upper interval.
There is therefore no eligible polynomial root even before filtering curve
liftability. Clearing denominators cannot have hidden an eligible solution.

This completes the all-r exclusion of a four-root arithmetic progression.
For any shared valid signature `(r,s)` and three distinct keys Q_i, the
recovered points in contexts z1,z2 satisfy

```
R_i,2 = R_i,1 + [(z2−z1)/s]G.
```

Their three-point overlap must have zero translation. Since s is nonzero,
**z2=z1 modulo n**. If the signature has only two recovery roots, three
distinct verifying keys are already impossible. Thus no case is omitted.
This global algebraic statement does not supply digest-byte extraction,
an ALL-only guard for a variable signature, or an output reference.

The JSON also records a direct **variable-signature** layout. Its entry is
`sigma Q0 Q1 Q2`; it retains those four items, checks the three key sizes
and inequalities, copies the same sigma for all six checks across the two
contexts, then removes the four originals. The raw layout is **76 bytes,
48 counted non-push operations, 4 entry data items (one signature and three
keys), 0 hints and combined peak 7**. All data coexist at entry and the
altstack is empty. These are layout counts only, excluding input pushes,
the wrapper and transaction, with no Core execution. The theorem applies
to that shared signature without fixing r, but the layout does not restrict
its sighash byte to ALL.

For boundary execution, `variable_signature_layout(code_separator=False)`
omits the separator so all six native checks have the same context. It is
**75 bytes and 47 counted operations**, with entry order **bottom to top:
sigma, Q0, Q1, Q2** and the same four data items, zero hints and peak seven.
The analogous literal generator `layout(3,1,code_separator=False)` is 123
bytes and 41 operations. These same-context variants allow honest execution
fixtures; they must not be presented as two different native contexts with
an equal hash.

An independent root-agent certificate is now available in
[r9_recovery_audit.json](r9_recovery_audit.json). It reconstructs the tripling
polynomials and uses a 9-by-9 companion-matrix Frobenius computation rather
than this implementation's polynomial gcd/factoring. Its ranks reproduce
the exact field-root counts 3 and 0 and the interval exclusion. That
independent host audit does not itself execute Bitcoin Script.

## 5. Public point offsets do not recover an output advantage

If a construction could natively enforce a common scalar offset u between
the two context keys, substitute `P2=P1+uG` into the same equations. Then

```
(z2−z1+2u)G = tR2−R1.
```

A common offset merely translates the tested point. Its maximum multiplicity
does not change, so it cannot permit two shared/offset-paired keys for the
t=2 family. Actual Script authentication of the point addition is another
obligation; granting it here does not avoid the exact obstruction.

Allow different arbitrary public point offsets instead. They can be chosen
without discrete logs:

```
T_i = (2R'_i−R_i)/2,
P_i(z) = (R_i−zG)/2,
Q_i(z) = P_i(z)+T_i = (2R'_i−zG)/2.
```

The same precomputed T_i now aligns the s=1 and s=2 checks for **every** z.
The executable fixes four offsets, switches between the two x-coordinate
families, and verifies 32 key pairs across eight deterministic scalar
digests. All signatures verify. No native mechanism checking those additions
is supplied, but even granting such checks the construction has exactly the
same public witness algorithm for an unauthorized output digest. Retaining
the offsets or any setup state does not create a distinction.

A limited additional check compares all eight nonzero root-switch points
with `[j]G` and `[j/2]G` for nonzero integers −256<=j<=256. None of the 768
distinct tested public scalars matches. This excludes only that explicitly
tested short-offset portfolio. It does not prove that no useful scalar
relation among A and B exists, and it is not a discrete-log hardness result.

## 6. Honest work, funding and the remaining scope

The two-common-key mixed-literal candidate has no valid witness even before
funding is considered, so it cannot meet any honest-work budget. Relaxing it
to one common key leaves the 16 fixed point targets in (1). Given one native
digest, obtaining the other digest for a chosen nonzero target still requires
an actual scalar/hash relation; presenting a point as the supposed digest
does not satisfy CHECKSIG. No sub-2^64 solver for those native contexts is
provided here. Generic hash or group estimates would be model assumptions,
not consequences of the finite enumeration.

The public-offset version has inexpensive witnesses but works for every
output digest. Hardcoding an adapted recovery key to a chosen reference
digest instead changes the locking script, funding transaction id and then
the actual ALL digest. The allowance to audit an intended spend before
publishing funding does not automatically solve that cycle. A mandatory
reference evaluator would still be needed.

The mixed-literal exclusion covers r=2, s1=1 and the stated second scalars;
the three-common-key equality theorem covers every valid shared ECDSA
signature on secp256k1. Arbitrary large mixed scalar ratios, different
signature graphs and new authenticated native point relations remain open.
The r+n exception has been handled explicitly throughout; it has not
supplied the required output-reference asymmetry.

## 7. Separate Core boundary results and independent readback

The root agent's [Core runner](r9_recovery_core.py) and
[recorded results](r9_recovery_core.json) exercise the **same-context
variable-signature variant** against isolated Bitcoin Core 30.3 at revision
`49faec4f87f5cd19c88db01a82e5c68b087c8227`. Four witnesses use
`(r,s)=(2,1),(4,2),(6,17),(16,129)`, each taking three of the four recovery
keys and omitting a different root index. All four receive consensus and
policy acceptance: evidence `differentially-validated`, deployment
`policy-validated` for those particular complete spends.

Their measured complete-transaction boundaries are: 23-byte P2SH funding
locking script; 75-byte redeem script; four entry data items (signature plus
three compressed keys); **zero hint items**; five scriptSig pushes including
the redeem script; 188-byte scriptSig for the first three cases and 189 bytes
for s=129; zero serialized witness bytes; respectively **1,080, 1,080, 1,080
and 1,084 WU**. The combined stack peak is seven, with 47 executed redeem
operations plus two P2SH-wrapper operations. All four data items coexist at
entry; no batching or streaming hides additional hints.

Four malformed or inconsistent witnesses reject: a duplicate key, an
uncompressed key, a changed signature, and the same three-key witness checked
under a genuinely different CODESEPARATOR context. The successful fixtures
all have identical contexts; no reference-hash collision or cross-context
equal-hash witness was mined.

An independent read-only audit reconstructed both legacy ALL preimages from
each of the eight recorded serialized transactions, checked the signature
encoding/flag and ECDSA equations, and replayed the raw PICK, size, inequality,
cleanup and context-selection stack operations. It agrees with all eight
stored outcomes and reproduces the positive stack/opcode counts, txids and
weights. The funding serialization also reproduces six 1,000,000-satoshi
test outputs plus 4,993,990,000 satoshis of change, leaving a 10,000-satoshi
fee from the 50 BTC coinbase. This readback did not start another Core process.

The consensus fixtures establish the native interface and reject malformed
keys; the exact all-r polynomial certificate establishes the universal
translation property. Neither supplies the still-missing mandatory output
reference.

Reproduce with `python3 research/covenant-2026-09-17/continuation/r9_four_roots.py`.
