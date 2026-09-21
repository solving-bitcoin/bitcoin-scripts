# R10: two distinct parallel ECDSA key cycles

Question: does duplicating a native ECDSA key cycle, sharing every signature and
context but requiring different keys at each vertex, remove its cheap odd-parity
closure while retaining one useful multi-digest equation?

**Result.** With two nonce roots and prescribed `r`, duplication does remove
odd parity, but also imposes a separate digest-ratio equality at every vertex.
With known nonce logarithms, free `s` can satisfy the remaining width equations; it cannot alter those
center equalities. If `r` is relaxed to an arbitrary nonzero scalar, the local
equations reduce to one **multiplicative** digest relation and one common scale.
Actual ECDSA still requires all those `r` values to be nonce x-coordinates. This
report supplies no sub-2^64 honest algorithm for that missing step. Four-root
signatures evade the zero-center formula through explicitly described point
offsets; they are not silently ruled out.

Files: [`r10_parallel_cycles.py`](r10_parallel_cycles.py) and its deterministic
[`JSON result`](r10_parallel_cycles.json). Evidence: `locally-reproduced`.
Deployment: `unclassified`. No Core execution, funded transaction, library
change, or repository field test is claimed. These are inspectable raw boundary
vectors, not measurements of a policy-compiled library primitive.

## 1. Exact two-root equations

Work in the secp256k1 group of prime order `n`; all scalar equations are mod `n`.
Edge `i` uses the *same complete signature bytes* `sigma_i=(r_i,s_i,flag_i)`
under `P_i,Q_i` at native digest `a_i`, and under `P_(i+1),Q_(i+1)` at native
digest `b_i`. Both checks at one end share one CODESEPARATOR context. Require
canonical 33-byte public keys and `P_i != Q_i` at every vertex.

For the moment the nonce recovery set is exactly `{R_i,-R_i}`. ECDSA gives

```
r_i P_i + a_i G = s_i U_i
r_i Q_i + a_i G = s_i V_i,
```

where `U_i,V_i` are distinct and therefore opposite. Define pair center
`C_i=(P_i+Q_i)/2` and half-width `D_i=(P_i-Q_i)/2 != infinity`. Then

```
C_i       = -(a_i/r_i) G,
C_(i+1)   = -(b_i/r_i) G,
D_i       = ±(s_i/r_i) R_i,
D_(i+1)   = ±(s_i/r_i) R_i.
```

At vertex `i`, comparing its incoming and outgoing edges consequently forces

```
b_(i-1) / r_(i-1) = a_i / r_i.                         (1)
```

This is an exact necessary condition, independent of `s`, key logarithms,
or whether the creator retained them. The two parallel copies cannot choose
independent edge parities: their two roots are opposite at each end, so both
copies have the same relative sign `tau_i`. Therefore

```
D_(i+1) = tau_i D_i,      product_i tau_i = +1.          (2)
```

An odd product would imply `D_0=-D_0`, hence `D_0=infinity`, contradicting key
distinctness. This proves the proposed odd-closure repair, while (1) proves the
extra local constraints it introduces. In the old single-copy odd cycle the
initial key is uniquely determined by the digest tuple; a second copy with the
same parities cannot choose a different initial key.

With fixed `r_i` and free `s_i`, (1) is one equality per vertex, rather than only
the balanced cycle's weighted sum. These equalities use distinct native context
hashes in the proposed raw layout. If every `r_i` is the known `x(G/2)`, they
are the full scalar equalities `b_(i-1)=a_i`. Eliminating signs does not make
these separate native hashes independently programmable.

### Complete conditional honest algorithm

Suppose every `R_i=k_i G` has a known nonzero nonce scalar, and (1) already
holds. Choose any public nonzero `w`, define

```
c_i = -a_i/r_i,
P_i = (c_i + delta_i*w)G,
Q_i = (c_i - delta_i*w)G,
s_i = w*r_i/k_i,
```

where each `delta_i` is either sign. Exclude the finitely many `w` producing
an infinite key, and normalize each signature to low-S; this only changes its
root orientation. All four checks on every edge then hold. No secret erasure
or signature search occurs. Thus for **known nonces and free signatures**, the
center conditions are sufficient as well as necessary. This is conditional
on native hashes satisfying (1), not a method of manufacturing such hashes.

For fixed `s_i`, the additional necessary and sufficient width condition is
that all points `±s_i R_i/r_i` agree up to sign. If `k_i` are known, the scalar
widths `s_i k_i/r_i` must agree up to sign. Prescribing signatures can therefore
add restrictions; it cannot remove any condition in (1).

The reproduction checks all four ECDSA equations at every edge for 3-, 4-, and
7-vertex constructed scalar fixtures, with different known nonces. It records
every scalar and signature, verifies local center equations, and rejects a
one-unit mutation of one context. These **constructed contexts are not native
transaction hashes**. A separate exhaustive pass covers all 1,020 sign
patterns for cycle lengths 2 through 9: 510 even products and 510 excluded odd
products.

## 2. What freeing `r` actually buys

If all context scalars are nonzero, (1) implies

```
r_i/r_(i-1) = a_i/b_(i-1),
product_i a_i = product_i b_i.                          (3)
```

Conversely, if the product equation holds, choose any nonzero `r_0` and use
the recurrence to obtain all other `r_i`; the closing local equation follows.
Thus a purely scalar relaxation leaves one global **product** relation and one
arbitrary scale. The executable fixture demonstrates this equivalence, and a
one-scalar mutation breaks its closing product condition. Zero context scalars
require the corresponding adjacent scalar to be zero too; the ratio form (3)
does not cover those cases. The undivided equations (1) remain valid.

But an ECDSA `r_i` is not an independently selectable scalar coefficient:

```
r_i = x(k_i G) mod n.
```

Choosing known `k_i` first fixes the `r_i` and returns to all the local
conditions. Choosing native hashes first and solving (3) only constructs
formal `r_i`; lifting these x-coordinates does not reveal their nonce
logarithms, needed by the conditional algorithm above. Generic recovery of
a prescribed point's logarithm costs about 2^128 group operations. This is an
estimate for that method, not a lower bound against all structured nonce
constructions or multi-list searches. The remaining concrete open problem is
whether a jointly chosen family of known nonces, native hash contexts and a
single scale can satisfy the local ratios below the total honest budget.
This report does not establish an impossibility theorem for that problem.

The same formula describes a two-key cross-signature reference interface. If
`alpha` checks both keys at constant digest `C`, and `beta` checks both keys
at output-committing digest `z`, with two roots for each signature, then

```
r_beta = (z/C) r_alpha,
s_alpha R_alpha/r_alpha = ±s_beta R_beta/r_beta.
```

For the legacy out-of-range SINGLE bug, the digest bytes are `01` followed by
31 zeros, hence the ECDSA scalar is **C=2^248**, not 1. A separate ALL signature
on the same input is allowed; SINGLE on one signature does not force SINGLE
on the other. This arrangement supplies a constant native reference but
leaves precisely the nonce-coordinate ratio obligation above.

## 3. Full four-root exception

For each edge let `S_i={±A_i,±B_i}` where `x(A_i)=r_i` and
`x(B_i)=r_i+n`. For an ordered distinct root pair `(U,V)` at one endpoint,
write `M=(U+V)/2` and `W=(U-V)/2`. The actual key pair then satisfies

```
C = (s_i/r_i) M - (z/r_i)G,
D = (s_i/r_i) W.
```

At each shared vertex the **complete** compatibility equations are therefore

```
(s_prev/r_prev) W_in = (s_i/r_i) W_out,
(a_i/r_i - b_prev/r_prev)G
    = (s_i/r_i) M_out - (s_prev/r_prev) M_in.            (4)
```

There are twelve ordered distinct pairs, rather than only the two opposite
orderings. Equations (4), together with legal curve roots and nonzero signature
scalars, are exact; a construction must satisfy both. An unqualified assertion
that two keys always impose zero-center digest ratios would be false.

For fixed four-root `r` and equal scale `s/r` across adjacent edges, matching
widths has a particularly small state machine:

| Ordered root difference | Representations | Possible pair centers |
|---|---:|---|
| `±2A` | one each | zero |
| `±2B` | one each | zero |
| `±(A-B)` | two each | `±(A+B)/2` |
| `±(A+B)` | two each | `±(A-B)/2` |

There are 20 ordered-pair transitions preserving a difference: 12 identity
transitions and 8 nonidentity transitions. Nonidentity root translations are
exactly `±(A+B), ±(A-B)`, each with two matching roots. This table is reproduced
on full secp256k1 for literal `r=2`; JSON records all twelve ordered pairs,
eight difference values, and twenty transitions.

The classification also holds for every four-root `r` given the independently
audited R9 certificate excluding `B=±3A` and `A=±3B`. Those are the only extra
root-difference collisions beyond `A=±B`, which is already excluded by the
different x-coordinates. See [`r9_four_roots.md`](r9_four_roots.md), its exact
polynomial certificate, and the parent's independent companion-matrix check.

For equal signature scale, a nonzero local digest offset consequently needs

```
(a_i-b_prev)G = s * H,
H in {±(A+B), ±(A-B)}.                                 (5)
```

The tiny literal `r=2` makes all four root points publicly computable. It does
not supply their logarithms or the logarithms of the four points `H`. Merely
choosing `s` or choosing an output digest does not solve (5). Repeated equations
can imply useful scalar relations after eliminating `H`, but at least one
nonzero point equality still has to be realized. Setting every translation
to zero returns to the local equalities. Changing signature scales introduces
the first equation of (4): ratios between root differences are additional
unknown-log relations unless a constructive relation is supplied. We do not
claim that all possible scales or different four-root `r` have been excluded.

R9's three-key theorem applies to three common distinct keys for the **same
signature** in two contexts. It does not directly transfer across two different
signatures. Requiring three parallel keys at every endpoint would also rule
out every two-root nonce; this is not a free repair of the known-nonce strategy.

## 4. Native Script shape and measured boundary

For `m` vertices the entry stack, bottom to top, is

```
P0 Q0 ... P(m-1) Q(m-1) sigma0 ... sigma(m-1).
```

Every key gets `SIZE 33 EQUALVERIFY` and each pair gets byte inequality. Native
CHECKSIG point parsing together with 33-byte length ensures a unique compressed
encoding, so the inequality is a point inequality. For each edge:

```
copy sigma_i, copy P_i, CHECKSIGVERIFY
copy sigma_i, copy Q_i, CHECKSIGVERIFY
CODESEPARATOR
copy sigma_i, copy P_next, CHECKSIGVERIFY
copy sigma_i, copy Q_next, CHECKSIGVERIFY
CODESEPARATOR before the next edge, if any
```

The bytecode preserves the original pool with PICK. Its two checks at one end
therefore have exactly the same signature and scriptCode. No signature can
match its one-byte numeric pushes in legacy FindAndDelete. Cleanup consumes
all original items and returns a single true. The final complete predicate's
non-push count is `25m + (2m-1) + ceil(3m/2)`; a 60-byte signature cap checked
on its first copy adds `3m`. All pushes count in the combined stack peak even
though they are omitted from the 201-opcode tally.

| Shape | Raw redeemScript | Counted ops | CHECKSIGs | Entry data | Hints | Peak |
|---|---:|---:|---:|---:|---:|---:|
| 7 vertices, separate contexts | 330 B | 199 | 28 | 21 | 0 | 24 |
| 6 vertices, separate contexts, signature SIZE<=60 | 304 B | 188 | 24 | 18 | 0 | 21 |
| 8 vertices, separate contexts | 387 B | 227 | 32 | 24 | 0 | 27 |

The first two fit the counted-opcode and 520-byte P2SH redeemScript limits;
this does not establish consensus or relay acceptance. The eight-vertex shape
exceeds the 201-opcode rule and is `consensus-incompatible`. No canonical
sighash-flag restriction is claimed; honest fixtures supply ALL, while the
raw predicates permit other valid flags. Consequently these are graph-relation
research interfaces, not complete exact-output covenants.

As a useful native-hash control, omit CODESEPARATOR. The seven-vertex variant
then has 317 bytes and 186 ops. All contexts hash the same transaction, so use
one known `G/2` nonce and the same public key pair at every vertex. Two unfunded
legacy ALL transaction vectors with different output scripts both pass the
independent ECDSA and restricted raw-stack replay. Each has 21 entry data items,
zero auxiliary hints, 22 scriptSig pushes including the redeemScript, 1,223
scriptSig bytes, zero serialized witness bytes, and weight 5,228 WU. Peak is
24. A P2SH output would be 23 bytes. These are **unfunded controls**: no funding
work or UTXO is omitted from an allegedly completed covenant construction.

Restoring CODESEPARATOR yields fourteen distinct native context scalars in
the seven-vertex transaction template, and all seven fixed-common-r local
equalities fail. The reproduction also exercises the six-vertex size-capped
control. This separates a working native same-context witness from the still
unsolved distinct-context honest search. It does not substitute chosen scalar
digests for actual transaction hashes.

Reproduce with:

```
python3 research/covenant-2026-09-17/continuation/r10_parallel_cycles.py
```

The algorithm uses fixed SHA256 labels and exhaustive loops, with no RNG seed
or external package. Source of the ECDSA recovery equation: SEC 1 v2.0,
21 May 2009, [§4.1](https://www.secg.org/sec1-v2.pdf). Curve parameters:
SEC 2 v2.0, 27 January 2010,
[§2.4.1](https://www.secg.org/sec2-v2.pdf). Bitcoin context semantics are the
same pinned Core rules already reproduced in the preceding R9 artifacts;
this R10 program does not invoke Bitcoin Core.

## 5. Independent readback of the same-input reference interface

The same reproduction reads the parent's
[`r10_reference_interface.json`](r10_reference_interface.json) without
importing or calling its serializer, signature-deletion routine, or `run()`.
It independently reconstructs the two-input legacy preimages and verifies all
256 flag outcomes, the four native ALL output variants, and the four literal
SINGLE/ALL context cases. It confirms `C=2^248` and that `C+n>=2^256` leaves
only one 256-bit digest encoding of the target scalar.

Independent opcode-boundary deletion removes the three copies of the matching
literal signature from each 123-byte script, giving two distinct 93-byte
scriptCodes. A local stack replay at the **hypothetical target** where both
digest scalars equal C confirms six checks, 41 opcodes, and peak six; this
does not claim any of the actual ALL hashes equals that target. The sixteen
nonce-scaling vectors are rechecked against their public nonce scalars,
low-S normalization, both distinct public keys, and a changed-target rejection.
The eight constant-digest flag cases are exactly 3, 35, 67, 99, 131, 163, 195,
and 227. These include undefined encoding flags in a host hash model, not a
claim of policy-valid signatures for all eight byte values.

No critical issue was found. The JSON records the audited snapshot's SHA256;
the existing elliptic-curve arithmetic helper is shared, so this is an
independent serialization/stack/algebra audit, not an independent EC
implementation or a new Core differential result.
