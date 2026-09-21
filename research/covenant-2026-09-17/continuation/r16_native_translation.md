# R16: closing an affine three-key translation against an actual digest

Question: can the mismatched antipodal case from R15 choose its translation
so that one signature uses the fixed SINGLE-bug digest C and the other uses
the actual ALL digest, including the funding outpoint and intended outputs?

The native-message equation can be eliminated exactly. A deterministic
small-curve analogue closes it against SHA256-derived transaction digests,
including two different recipients under the same funding and source alpha.
It does not supply a secp256k1 construction, a raw 32-byte hash interpreted
as a DER signature, or an honest-work bound below 2^64.

Evidence: `locally-reproduced`; deployment: `unclassified`.
[Python](r16_native_translation.py) and [JSON](r16_native_translation.json)
contain complete serialized transactions, hash preimages, signatures, every
toy group logarithm, two positive raw-script replays and three targeted
negative replays. This is a host-side small-curve interpreter, not Bitcoin
Core or Bitcoin consensus execution. No library or field-library tests run.

## Eliminate the translation without treating the native digest as free

Use R15's source mixed pair A,B with different x branches and
`V=(A+B)/2`. The source digest is C. Write z for the actual target ALL
digest scalar, and `(ri,si)`, `(rj,sj)` for the two signatures. The common-key
map and mixed-pair cancellation give

```
a = rj*si/(sj*ri),
b = (z-rj*C/ri)/sj,
a*V+b*G = O.
```

Multiplying out eliminates a,b and sj:

```
rj*(si*V-C*G) = -ri*z*G.                         (1)
```

If `V=vG` has a known logarithm, then

```
v = (C-z*ri/rj)/si,
rj = z*ri/(C-si*v),       when C-si*v != 0,
sj = rj*si/(a*ri).                              (2)
```

All divisions here are modulo the group order n. Equation (1) is a necessary
pair-center condition; the third common key, destination roots and valid
signature ranges still require checking. For a hash-chosen ri, the four
source nonce points can be recovered publicly, but this does not provide
the scalar v. The toy algorithm explicitly computes the complete group
log table first; it never treats those logarithms as free on secp256k1.

Set `W=si*V-C*G`. If W is infinity and z is nonzero, (1) is impossible.
If W is finite and z is zero, nonzero rj<n cannot satisfy (1). If both W
and z are zero, (1) imposes no restriction on rj, but every other root and
signature condition remains. The two executable fixtures use z nonzero.
The source antipodal pair V=O is a different, known-center case already
included in the five-center analysis below.

## One concrete digest-first algorithm and its cost

Without log(V), W is still a public point. For each source mixed pair, after
computing the actual z, solve the bounded discrete-log equation

```
rj*W = -ri*z*G,       1 <= rj < Delta=p-n.
```

A classic baby-step/giant-step implementation uses
`L=Delta-1`, `m=ceil(sqrt(L))` baby entries and `ceil(L/m)` giant queries.
The complete or unsuccessful scan needs `m+ceil(L/m)-2` point additions
before extra scalar multiplications, comparisons and index costs. For
secp256k1 these counts are

```
L                = 432420386565659656852420866390673177325
m                = 20794720160792249932
point additions  = 41589440321584499862 ≈ 2^65.172851
point bytes alone= 686225765306144247756
```

The point-byte count uses 33 bytes per baby point and excludes indices and
hash-table overhead. The complete-scan count is not an expected successful
solve. Conditional on a uniformly located solution in the interval, the
cost is approximately `m+L/(2m)`. Optimizing m gives about
`sqrt(2L)=2^64.672851` additions; the JSON also gives the exact rational
expectation for an integer m. Most independent digest values have no
interval solution for a fixed nonzero W: its scalar support has only L
elements out of n. Full scans therefore matter for this digest-first route.

These are estimates for this explicit classical algorithm, not a universal
lower bound or an implementation benchmark. No secp256k1 interval search
was run. This method also leaves the destination sj obligation: if a
destination nonce root T is selected, the equation
`sj*T=rj*K+z*G` can itself require a discrete logarithm. The construction
does not grant an algorithm that computes it cheaply.

## Executable small-curve closure with all state retained

The fixture uses `p=163`, `n=139`, `G=(2,34)` and retains all 139 group
points indexed by scalar. The four-root r values are exactly 6,9,13,21.
The source constant is `C=2^248 mod139=136`, from the legacy SINGLE-bug
digest bytes `01` followed by 31 zero bytes.

First fix a 79-byte P2SH-shaped redeemscript. A synthetic funding transaction
F pays output 0 to OP_TRUE and output 1 to its P2SH commitment. F's txid is

```
0a10bcc2f98e90cdc97d07eee2e144e9c59373cec8ed09400187bcfaebba850a
```

The child spends both F outputs and has one output. At current input 1 the
source SINGLE signature therefore uses C; the other signature uses the ALL
preimage containing the complete two F outpoints and the full redeemscript.
No literal alpha or beta push occurs in the script, so legacy FindAndDelete
does not remove either signature from scriptCode. The funding input is a
synthetic outpoint, not a funded on-chain UTXO. This serialization follows
the [pinned Core legacy signature-hash implementation](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp).

F is fixed before searching source alpha. For counter encoded little-endian
in four bytes, compute

```
H = SHA256("r16 public source scalar projection" || counter)
ri = 1 + int(H[0:16]) mod(n-1)
si = 1 + int(H[16:32]) mod((n-1)/2)
alpha = DER(ri,si) || 03.
```

This is an explicit projection into toy signature scalars. It is **not**
raw32-byte H interpreted as DER. The raw script also does **not** execute
this hash projection or authenticate alpha's hash provenance. Both are
missing obligations for the main construction, not properties established
by the fixture.

At counter 2515, after 2516 source SHA256 queries, the projection gives
`ri=9,si=8`, alpha `300602010902010803`. Its SHA256 output is

```
96535454adfb8c963800864d61dcd3182a6be0802c129ec2a4141b3f92bbc0ff
```

For each actual digest the algorithm enumerates mixed source pairs, computes
v from its retained scalar table, solves rj using (2), and tests destination
four-root candidates. It obtains sj from the known toy destination nonce
scalar, then checks the full common-key intersection. No digest is replaced
by a desired algebraic value.

| Recipient | Locktime | Actual z | v | rj,sj | a,b | Common key scalars |
|---|---:|---:|---:|---|---|---|
| P2WPKH `11` repeated 20 bytes | 0 | 134 | 44 | 6,10 | 121,97 | 19,20,28 |
| P2WPKH `22` repeated 20 bytes | 14 | 1 | 95 | 6,10 | 121,42 | 19,27,28 |

Each output pays 999000 satoshis. The second row uses 15 ALL queries, with
the same F, source alpha and source hash preimage. The actual 256-bit ALL
digests, before reducing modulo139, are respectively

```
069fa3114d6d846dcbf605c4ee15e9338b1698a401696250bf89dc84e13d018f
954ba29b68b5e95831bd2f7d92bc9102892e0082e242fa348a34ea7bbf19014a
```

Both rows happen to use the same beta `(6,10)||01`. Their common-key sets
differ and have intersection of size two; the fixture does not contradict
the same-signature/three-fixed-common-keys uniqueness result. This is also
not a Bitcoin covenant counterexample: it exhibits a freely selected toy
reference interface that closes for two outputs. Closure alone has not
authenticated an intended recipient.

## Complete raw predicate and targeted rejection checks

Entry is exactly `[alpha,beta,K1,K2,K3]`: **five data items, zero hints**.
The script checks depth five, 33-byte key lengths and pairwise byte
distinctness, then verifies alpha and beta under each key and finishes with
one true stack item. The host interpreter implements the corresponding
ECDSA equations on the toy group. Its 33-byte compressed key encodings
imitate Bitcoin's format but contain toy points; they are not secp256k1
public keys.

Each positive run has 50 nonpush opcodes, 79 script bytes, combined stack
peak 8 and six ECDSA checks. All five data items coexist at script entry;
there is no altstack or composition claim beyond this fragment. The complete
synthetic unlocking script has six pushes including the redeemscript and
203 bytes. It has no witness field, so serialized witness bytes are zero.
The complete child is 326 bytes / 1304 weight units. Both runs together
perform 12 toy ECDSA checks.

Three minimal negative checks pass: duplicating the third key is rejected;
changing to the second recipient/locktime while retaining the complete first
witness is rejected; changing source s from8 to9 is rejected, with all three
individual source ECDSA checks false. The successful second output requires
its different supplied key set. No script binds that set to an intended
output or binds alpha to the recorded source hash.

## Consequence and falsifiable next construction

The independently checked [five-center support result](r16_three_key_support.md)
covers every affine translation for fixed alpha and constant C, without
computing any pair-center logarithm. It bounds possible native digest scalars
by `5*(Delta-1)`; the accompanying fresh independent source/native hash model
rules out merely choosing another translation as a cheap search strategy.
That result explicitly excludes shared or correlated oracle answers, such
as alpha equal to the actual native digest. This toy projection is not a
demonstration of such an exception.

A next constructive candidate must provide exact secp256k1 hash input bytes
and their raw32-byte DER alpha, the actual funded ALL digest, three finite
distinct common keys, and a Script-enforced relation to the chosen output.
It must account for any pair-center/destination logarithms and for the joint
hash search, including a concrete correlation if it relies on escaping the
independent-answer support bound. The finite equation (1) and the full raw
replay provide checkable acceptance conditions. None of those missing
Bitcoin-scale obligations is supplied here.
