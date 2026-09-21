# R11: native digest-first nonce ratios from the secp256k1 endomorphism

Question: can the known secp256k1 endomorphism realize the R10 two-key
constant-message/ALL ratio for an **actual digest chosen first**, with every
field/order wrap accounted for?

**Yes, when the reference signature alpha is freely chosen.** An exact
two-dimensional integer lattice finds suitable nonce points for a supplied
ratio `u=z/C`, where `z` is already the native ALL digest and `C=2^248` is the
legacy SINGLE-bug scalar. The known endomorphism supplies the scalar ratio
between the two nonce points. Neither nonce's discrete logarithm is needed.
Eight different unfunded transaction templates pass all four native ECDSA
equations and a local raw-stack replay, after respectively 1, 5, 1, 1, 2, 1, 1,
and 3 locktime candidates.

This corrects an overly broad reading of the preceding ECDLP obstacle: a
**fixed** alpha leaves a fixed nonce coordinate and a small target catalogue;
a freely selected alpha can instead be constructed after the native hash.
The latter is a useful new reference-interface witness algorithm, but also
works for arbitrary changed output scripts. It does not bind alpha to a
readable proof hash or distinguish the required outputs.

Evidence in this report: `locally-reproduced`. Deployment: `unclassified`.
No Core run, funded transaction, hash-derived alpha, or full covenant is
claimed here. The parent separately tests funded instances. Code and results:
[`r11_endomorphism.py`](r11_endomorphism.py),
[`r11_endomorphism.json`](r11_endomorphism.json).

## 1. Public endomorphism and exact wrap equation

Let `p` be the field prime, `n` the group order, and `Delta=p-n`. The standard
secp256k1 constants satisfy

```
phi(x,y) = (beta*x mod p, y) = lambda*(x,y),
beta^3 = 1 mod p,   lambda^3 = 1 mod n,
beta != 1,         lambda != 1.
```

The reproduction derives `beta=2^((p-1)/3) mod p` and
`lambda=3^((n-1)/3) mod n`, checks their standard constants, and verifies the
endomorphism relation on G and on every final witness point. These are the
parameters documented in libsecp256k1 **v0.6.0**,
[scalar_impl.h](https://github.com/bitcoin-core/secp256k1/blob/v0.6.0/src/scalar_impl.h)
and [field.h](https://github.com/bitcoin-core/secp256k1/blob/v0.6.0/src/field.h).

For `j=1` or `2`, put `B=beta^j mod p`, `t=lambda^j mod n`. Given
`R=(x,y)`, write the integer representatives as

```
x = r + a*n,          a in {0,1},
x' = B*x - q*p = r' + b*n,    b in {0,1},
q = floor(B*x/p).
```

Reduction modulo n gives the **exact** relation

```
r' = B*r - q*Delta mod n.                              (1)
```

The large quotient term cannot generally be dropped. In particular,
`r'/r` is not universally `B mod n`, nor `t mod n`. The `a*n` and `b*n`
terms really cancel modulo n; the `q*p` term leaves `q*Delta` behind.
Twenty-four full-size vectors include both `x=r` and `x=r+n`, both transformed
wrap directions, literal four-root values `r=2,4`, G, and G/2. The JSON
records every quotient and whether the naive no-correction formula happens
to hold for that individual vector.

## 2. Solving a supplied target ratio using a lattice

For supplied canonical nonzero `u`, the desired relation is

```
x' = B*x mod p,
x' = u*x mod n,
1 <= x,x' <= p-1,
x mod n != 0,  x' mod n != 0.                           (2)
```

The second congruence automatically accounts for both possible n-wraps.
Chinese remaindering gives one integer `v mod p*n` with

```
v = B mod p,     v = u mod n.
```

All solutions of the two congruences are precisely the rank-two lattice

```
L_u = Z*(1,v) + Z*(0,p*n),
det(L_u) = p*n.                                        (3)
```

Integer Gauss reduction makes the basis short. The rectangle in (2) has area
approximately its determinant, so it often has a small number of nonzero
lattice points; area alone does not guarantee a solution. For each candidate
x the code tests whether `x^3+7` is a quadratic residue. A valid lift gives
`R_alpha=(x,y)` and `R_beta=(x',y)=t*R_alpha`, already satisfying the required
ratio of ECDSA r values.

The rectangle enumerator uses the inverse basis to bound its second integer
coefficient, then intersects exact integer intervals for the first coefficient.
It represents whole lines by intervals rather than assuming the rectangle
contains only a constant number of points. The public solver tests up to 128
candidate points per endomorphism. A return of `None` means no witness was
found within that explicit cap; it is not a universal nonexistence claim.

The API is:

```
solve(u, max_candidates=128, exponents=(1,2), max_r=None)
```

It accepts an arbitrary `u=z/C mod n` and returns the two affine points,
their public scalar ratio `t`, both `r` values, the reduced basis, and search
counts. It does not require a label-derived or manufactured target. Optional
`max_r` restricts the alpha coordinate to the exact strips described below.

Validation: 928 exhaustive rectangle/target cases at four small pairs of
distinct primes agree with direct enumeration of every x. These are tests
of the integer lattice enumeration, not substitute elliptic curves. At full
secp256k1 size, 43 of 64 deterministic independent target ratios produce a
valid point using one of the two nonidentity x maps, without changing the
target. The successful targets use 90–117 Gauss iterations. These counts are
observations, not a proved asymptotic success probability.

## 3. Complete native-hash witness algorithm

Use the fixed 44-byte raw script returned by `layout()`. Its entry stack is
`alpha beta P Q`; it enforces that P,Q are distinct 33-byte keys and then checks
alpha under both, followed by beta under both. It consumes the four original
items and returns one true. All checks share the same scriptCode, which contains
no literal signature pushes. Signature-specific FindAndDelete therefore has
nothing to remove.

The transaction places this locked input at index 1 and has one output. Its
alpha flag is `03`, giving the constant SINGLE-bug scalar C; beta's flag is
`01`, committing every output. The witness algorithm is:

1. Fix the input outpoints, the raw script, output amount/script and locktime.
2. Compute the actual legacy ALL digest `z`. No signature or public key is
   embedded in the script or funding template.
3. Run `solve(z/C mod n)`. If no point is found, try another permitted locktime.
4. Set `alpha=(r,1,03)`. Recover the public key pair
   `P,Q=(±R_alpha-CG)/r`.
5. Set `beta=(r', r'/(t*r),01)` and normalize beta to low-S.
6. Supply alpha, beta and the two compressed keys.

The four verification equations are

```
r*P + C*G = R_alpha,
r*Q + C*G = -R_alpha,
r'*P + z*G = (r'/r)*R_alpha = s_beta*R_beta,
r'*Q + z*G = -(r'/r)*R_alpha = -s_beta*R_beta.
```

Low-S normalization only exchanges the final two root signs. All nonce points
in the eight native fixtures have exactly two recovery roots, verified by
`r,r' >= p-n`; the method itself can still use an antipodal pair when an
additional lift exists. No creator secret or erased state is used. The
discrete logarithms of the constructed nonce points are not computed.

The fixed output script changes across eight fixtures, while the synthetic
prevouts and raw script remain the same. The eight successful searches use
15 native ALL digest candidates in total. Every stored preimage is the real
legacy ALL serialization of its specified transaction template; these are not
chosen scalar messages. Changing the accepted digest by one breaks double
acceptance under beta's retained keys. The raw predicates do **not** enforce
the supplied flags by byte extraction; the positive witnesses explicitly use
SINGLE and ALL. Even an ideal extra restriction to those flags would leave the
arbitrary-output witness algorithm intact.

Measured boundary:

| Item | Value |
|---|---:|
| Raw complete redeemScript | 44 bytes |
| Counted/executed non-push operations | 27 |
| ECDSA checks | 4 |
| Entry signature/key data | 4 items |
| Auxiliary hints | 0 items |
| Combined main-plus-alt-stack peak | 7 items |
| Signature lengths in native fixtures | alpha 40–41 bytes; beta 71–72 bytes |
| Complete scriptSig | 226–228 bytes; 5 pushes including redeemScript |
| Serialized witness | 0 bytes |
| Complete unfunded two-input transaction weight | 1,396–1,404 WU |

A P2SH funding output would have a 23-byte scriptPubKey. The host vectors are
unfunded; their purpose is native preimage and witness construction. The fixed
script is chosen before any funding, and the algorithm accepts whatever
funding outpoint later determines z, so it does not assume that a script
commitment can be changed after learning its funding txid. The parent is
responsible for any separate Core/funding evidence. No repository compiler
or general Script interpreter result is claimed by these raw-vector metrics.

## 4. Short alpha and hash-derived alpha are different obligations

For an exact 32-byte strict DER signature including its flag,
`n_r+n_s=25`. Since `s!=0`, `n_s>=1`, so `n_r<=24`. Positive minimal DER
encoding then implies

```
1 <= r <= Rmax = 2^191-1.
```

Its possible nonce x coordinates occupy exactly two possible strips:

```
[1,Rmax] and [n+1, min(p-1,n+Rmax)].
```

Their combined integer-coordinate count is at most

```
Rmax + min(Rmax,p-n-1),                                 (4)
```

not `2*Rmax`. The upper strip has only about 129 bits of width. For each fixed
endomorphism and each coordinate x there is only **one** target ratio
`u=(B*x mod p mod n)/(x mod n)`. The six automorphisms
`±1,±lambda,±lambda^2` give just three x maps: signs add no coordinates,
and the identity map only targets `u=1`. Therefore the two nonidentity x maps
have target support at most

```
S = 2*(Rmax+min(Rmax,p-n-1)) ≈ 2^192.                   (5)
```

For an independent uniform canonical target scalar, its probability of even
having such a short-r witness is at most `S/n`, approximately `2^-64`, **before**
curve lifting, the rest of the DER format, a required flag, or any proof-hash
binding. For an actual uniform 256-bit digest reduced modulo n and scaled by
`1/C`, the exact conservative bound is

```
(S + min(S,2^256-n)) / 2^256.
```

The second term accounts for scalars with two digest encodings. It is tiny
relative to S here; it should not be replaced by a blanket factor of two.
JSON records the exact integers rather than relying on rounded exponents.

The short-strip lattice algorithm is executable. Six planted 191-bit-coordinate
fixtures produce alpha signatures of exactly 32 bytes, but their ratios were
manufactured from those coordinates. Sixty-four independent target ratios
produce no short witness, as expected at this scale. The planted fixtures do
not establish cheap native target fitting.

Equation (5) is only a necessary-condition support bound. It already prevents
the full-length solver's observed constant-trial behavior from carrying over
to 32-byte alpha. A character-equidistribution heuristic would further halve
the support for curve lifting, suggesting about `2^65` target trials even
before other obligations; this heuristic is not used as a proved lower bound.
Each trial also performs native hashing and lattice arithmetic. No honest
sub-2^64 total-work strategy for this short-alpha route is supplied.

If alpha must equal a hash of a readable proof, satisfying its byte length
does not produce that preimage. Conversely, hash alpha first and its r value
is fixed. There are then at most two x lifts and two nonidentity endomorphism
choices, hence at most four target ratios, regardless of s. The lattice cannot
retarget a fixed r by choosing its point's y sign. A finite precomputed alpha
catalogue remains a full scalar native-target matching problem; the parent
separately audits that query bound. No independent searches or funding work
are silently omitted by calling alpha freely selectable.

## 5. Other structured families: many witnesses can share one target

Gauss reduction of the field-only lattice `(1,beta),(0,p)` gives the positive
relation

```
b = 303414439467246543595250775667605759171,
a =  64502973549206556628585045361533709078,
a = beta*b mod p.
```

For every positive h with `b*h<=Rmax` and `a*h<p`, choosing
`x=b*h`, `x'=a*h` incurs no field wrap. The same endomorphism gives

```
r'/r = a/b mod n
```

for **every** such h. There are `10,344,105,155,984,659,652` allowed h values
under the short-r bound. Three deterministic curve-liftable examples near
`h=2^62` yield exact 32-byte alpha encodings. They all have one fixed target
ratio. Thus this efficient large witness family improves neither the count of
accepted native targets nor the hash-preimage obligation. It is also a useful
case where the rectangle may contain many points: the solver's interval/cap
handling matters.

The order-three orbit explains the limitation for R10's multiplicative cycle.
Let `x_j=beta^j*x mod p`, `r_j=x_j mod n`, and
`u_j=r_(j+1)/r_j`. Then

```
u_0*u_1*u_2 = 1 mod n,
x_0+x_1+x_2 = h*p,   h in {1,2},
r_0+r_1+r_2 = h*Delta mod n.
```

Hence two proposed consecutive native ratios `u,v` force

```
r_0 = h*Delta/(1+u+u*v) mod n,   h in {1,2}.            (6)
```

The denominator cannot be zero for an actual orbit. There are at most two
r candidates, followed by their valid x lifts and exact endomorphism checks.
The product relation alone does not make every proposed native ratio triple
an endomorphism orbit. Four full-size public-nonce orbit vectors reproduce
all these equalities and all integer sum quotients. Satisfying one native
ratio with the new lattice solver does not automatically satisfy additional
independent native context ratios.

## Reproduction and remaining criterion

```
python3 research/covenant-2026-09-17/continuation/r11_endomorphism.py
```

All inputs are fixed labels, fixed transaction templates or exhaustive ranges;
there is no nondeterministic RNG. No library files or field-library tests
are changed. A useful next construction must preserve the digest-first
witness algorithm while binding alpha to the required readable reference
and the prescribed outputs, counting native hash generation, lattice work,
all alpha-preimage work, and funding. The present result establishes the
nonce-ratio step for freely chosen full-length alpha, and explicitly leaves
that binding obligation unresolved.

## 6. Independent readback of the parent's funded Core experiment

The parent subsequently produced
[`r11_endomorphism_core.json`](r11_endomorphism_core.json) using Bitcoin Core
30.3, commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`. Three recomputed public
witnesses for different recipients, including a changed amount, were accepted
by both the recorded relay policy and consensus checks. Three negative cases
were rejected. The positive funded results are `differentially-validated` and
`policy-validated`; that evidence applies to the free-signature pair interface,
not a hash-derived reference or covenant.

The independent `audit_core_artifact()` in this report's source reads the
parent's JSON without importing its transaction builder or running Core. It
parses each raw transaction, strips marker/flag and witness, recomputes txid,
wtxid and weight, reconstructs the actual legacy ALL preimage, and checks the
signature flags, ECDSA equations, point relation and raw stack predicate. It
also confirms that every spend uses the same funding vout 0 as the locked
second input and funding vout 1 as its ordinary first input.

The funding transaction has two 1,000,000-satoshi outputs and a
4,997,990,000-satoshi change output: 4,999,990,000 satoshis total. Against the
documented first-block 50 BTC coinbase, the fee is 10,000 satoshis. Its stripped
size is 169 bytes and its weight is 681 WU. The three accepted spends have
weights **1,406, 1,402 and 1,410 WU** and fees **10,000, 10,000 and 20,000
satoshis**. Each contains four serialized witness bytes plus two marker/flag
bytes: the ordinary input's witness holds the one-byte OP_TRUE script; the
locked P2SH input has no witness items. The locked predicate still has four
entry data items, no auxiliary hints, five scriptSig pushes, 27 opcodes and
peak seven.

The negative checks reproduce the intended causes. Keeping the old witness
after changing the output passes both SINGLE checks but fails both ALL
checks. Duplicating a key passes the four curve equations but fails the point
inequality. Changing alpha's s to 2 fails both alpha checks while beta's two
checks remain true. For the changed-output row, its stored
`all_preimage/all_digest/trace` describe the **original witness construction**;
the independent audit reconstructs the current transaction's changed digest
separately and confirms it equals the digest used by the recomputed recipient-B
witness.

No critical issue was found. The audit records the inspected JSON snapshot's
SHA256 and every reconstructed result in this report's own JSON. It shares the
existing host EC arithmetic helper and makes no claim to be another independent
EC implementation or an additional Core execution.
