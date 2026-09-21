# R12: hashing a live full-length endomorphism signature

Date: 2026-09-17. Question: can the actual-signature side of the R11
endomorphism interface acquire a hash reference without forcing its nonce
coordinate into the short-DER strips? The comparison counts native digest
generation, signature generation and hash trials separately.

**Yes for a live, opaque hash reference; no readable intended-output reference
has been obtained.** The reverse direction `h=SHA256(alpha)` preserves the
full-length nonce coordinate and a large public family of valid signatures
after one native digest has been fixed. A raw 55-byte script authenticates h
against exactly the alpha used in four native ECDSA checks. Forty-eight actual
native-digest witnesses pass, including changed output amounts and scripts.

Three different claims must remain separate:

1. The implemented script checks a **freely supplied h** equals the hash of
   the actual signature. Its hash and all four ECDSA equations are real.
2. A second raw layout would use the computed hash as a DER signature under
   a **freely recovered K**. Its public construction is derived below, but
   no rare hash-to-DER witness was mined and that layout was not executed.
3. Neither layout makes h a readable reference to the intended outputs.
   The large family changes alpha, and supplies no additional L transaction
   variants for a fixed alpha or fixed authenticated reference.

Evidence: `locally-reproduced` for the executed native-hash/curve equations
and limited raw-stack replay; deployment `unclassified`. These are host
experiments with synthetic prevouts. No Core run, funded transaction,
repository Script compiler/executor, rare hash-derived signature, complete
covenant, field-library test or primitive metric is claimed. Files:
[`r12_live_reference.py`](r12_live_reference.py),
[`r12_live_reference.json`](r12_live_reference.json).

## A scalar-homogeneous family after the actual digest

Let `C=2^248` be the legacy SINGLE-bug scalar. Put the covenant input at
index one in a two-input transaction with one output. Fix the raw script,
prevouts and output list; compute its actual ALL scalar z. R11's lattice
solver supplies points R,R', public t, and nonzero coordinates r,r' with

```
R' = t R,
r = x(R) mod n,       r' = x(R') mod n,
r'/r = z/C mod n.
```

For every nonzero s, define

```
alpha_s = DER(r,s) || 03,
P_s = (s R - C G)/r,
Q_s = (-s R - C G)/r,
b_s = r' s/(t r) mod n,
beta_s = DER(r', min(b_s,n-b_s)) || 01.
```

The required equalities are

```
r P_s + C G =  s R,
r Q_s + C G = -s R,
r' P_s + z G =  (r'/r)s R = b_s R',
r' Q_s + z G = -(r'/r)s R = -b_s R'.
```

Normalizing beta to LOW_S only exchanges nonce signs. Restricting
`1 <= s <= floor(n/2)` also makes alpha LOW_S and yields distinct canonical
alpha bytes. At most two s values over the entire nonzero group make one
key the point at infinity; excluding them suffices. Every remaining pair
is distinct because `P_s-Q_s=2sR/r` is nonzero. No discrete logarithm of R
or of either key is used. The host validates twelve s values per transaction,
including DER length boundaries, `s=1`, and `s=floor(n/2)`.

Consequently a fresh hash trial only serializes alpha_s and computes
SHA256(alpha_s). **No scalar multiplication or new native digest query is
needed per hash trial.** Compute P_s,Q_s and beta_s only after a desired hash
event. This reverses R11's constrained direction: alpha_s itself can have
40–72 bytes, while its 32-byte hash is a new object. The exact 32-byte DER
bound `r<=2^191-1` therefore does not restrict alpha_s. It would restrict the
r coordinate of a hash subsequently interpreted as its own DER signature.

The finite LOW_S family has almost `n/2` members, not a source of unlimited
independent samples. Distinct SHA256 inputs have independent outputs only
in the explicitly assumed fresh-query ideal-oracle model. The executable
checks 4,096 actual hashes for each of four native contexts: no duplicate
hashes and no DER-syntax hits occur in these 16,384 trials. This small sample
does not estimate a probability near `2^-45`.

## A. Implemented live-hash equality

The entry stack is exactly `[h, alpha, beta, P, Q]`. Prepend to the unchanged
R11 four-check layout:

```
DEPTH 5 EQUALVERIFY
4 ROLL TOALTSTACK
3 PICK SHA256 FROMALTSTACK EQUALVERIFY
```

This removes h from below the four native operands, hashes a duplicate of
the actual alpha, checks byte equality, and preserves the four operands for
their native checks. The suffix verifies alpha under P and Q, then beta
under P and Q, consumes them and leaves true. Every CHECKSIG uses the same
full scriptCode. There is no CODESEPARATOR or signature literal, so
signature-specific FindAndDelete does not alter any context.

The host computes the ALL digest using this complete 55-byte script, not
the preceding R11 script. The four native transaction templates vary the
recipient, amount, or output script, while keeping the synthetic prevouts
unchanged. Their lattice searches take 2, 1, 5, and 1 locktime candidates.
Each context then yields all twelve scalar-family witnesses without changing
its digest. There are 48 positives and 192 genuine ECDSA checks. All 24
negative cases reject: wrong h, h from another scalar, a changed alpha with
its correctly recomputed h but retained native keys, extra/missing entry
data, and a changed native digest.

The fixed script contains no h, alpha, key or other transaction-dependent
literal. Thus its commitment can be set before funding and the constructor
can take whatever funding outpoint is later produced. The tested prevouts
are nevertheless synthetic: that acyclic dependency argument is not a funded
or Core-validity claim. The host's positive signatures use SINGLE and ALL;
the script does not extract or enforce those flag bytes. The observed lack
of output asymmetry already holds when granting those honest flags.

| Complete raw boundary | Measurement |
| --- | ---: |
| Redeemscript bytes | 55 |
| Static and executed non-push operations | 35 |
| Native ECDSA checks | 4 |
| Entry data items | 5 |
| Auxiliary hint items | 0 |
| Combined main-plus-alt-stack peak | 7 |
| Actual sampled alpha lengths | 40–71 bytes |
| Actual sampled beta lengths | 71–72 bytes |
| scriptSig bytes, including redeemscript push | 270–302 |
| scriptSig pushes, including redeemscript | 6 |
| Serialized witness bytes | 0 |
| Complete synthetic transaction weight | 1,500–1,708 WU |

These are deliberately raw boundary vectors, not optimizer-produced library
metrics. Input pushes are excluded from the 55 script bytes and included in
scriptSig. The scriptSig numbers exclude its outer CompactSize length; the
transaction weights include it. All five data items coexist at script entry;
there are no incremental or hidden hint items. One copy reaches seven total
stack elements, well below 1,000. Repeated copies are not measured and the
exact-depth guard prevents silently appending other live operands beneath
this fragment. No default-relay acceptance is claimed.

## B. Derived, unmined hash-as-signature pin

Replace the prefix's final EQUALVERIFY by CHECKSIGVERIFY, with entry
`[K,alpha,beta,P,Q]`. The script computes `gamma=SHA256(alpha)` and actually
requires gamma under K before the same four checks. This prospective script
also has 55 bytes and 35 counted operations, five entry operands, zero hints,
and structural combined peak seven; success would execute five ECDSA checks.
There is no witness serialization or transaction-weight measurement for it.

If gamma is strict DER with nonzero scalars rho,tau and an accepted flag,
compute the **actual flag-selected native scalar** z_gamma of this new
script. For any valid recovery root W with `x(W) mod n=rho`, choose

```
K = (tau W - z_gamma G)/rho.
```

Provided K is not infinity, its native ECDSA check succeeds. Gamma was
derived from the actual alpha_s, not a substituted host signature. Generating
the inputs to this extra condition stays acyclic because K is witness data.
The relevant canonical rules are in
[Bitcoin Core v29.0, IsValidSignatureEncoding and CheckSignatureEncoding](https://github.com/bitcoin/bitcoin/blob/v29.0/src/script/interpreter.cpp)
and [BIP66](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki).

Using R5/R11's optimistic uniform 32-byte DER-syntax probability,

```
p_syntax = 780555/2^65,
1/p_syntax = approximately 2^45.42586 hash trials.
```

This is a conditional syntax-only query estimate, not a measured full-work
bound. Curve lifts, zero scalars, accepted flags, output-binding requirements,
DER serialization, hash implementation, lattice setup, recovery, transaction
setup and audit must all be accounted for in a complete construction. No
rare successful gamma was mined. No dummy or mocked ECDSA gate is presented
as a positive execution of this layout.

Keeping K free is crucial. If gamma must instead use the same known
endomorphism nonce R' and the same P_s,Q_s at the ALL digest z, its required
components are precisely

```
rho = r',
tau = ±r's/(tr) mod n.
```

That is a hash target tied to beta_s, rather than merely a DER event. Every
one of the four measured r' values exceeds `2^191-1`, so no 32-byte gamma
can even have that r'. This is a check of the **same known endomorphism
branch**, not a theorem about every four-recovery-root pairing or a general
native-key closure. Its purpose is to expose which freedom the free K adds.

## C. The still missing reference and fixed-alpha L

The implemented h is authenticated as the hash of alpha, but remains an
opaque 32-byte witness operand. The script performs no arithmetic decoding
or intended-output computation from h. The prospective gamma/K check also
does not perform one: any other output list can use the same public lattice
and scalar-family algorithm. This is directly witnessed for the live-hash
layout and is the same conditional sampler for the unmined pin.

In particular, **the approximately n/2 scalar choices are not L variants at
fixed alpha**. Each scalar produces a different alpha and generally a
different h, P, Q and beta. Once alpha is fixed, its r and s are fixed. The
R11 catalogue still gives at most two x lifts times two nonidentity
endomorphisms, hence at most four target scalars `z=C*r'/r`. Changing s no
longer supplies another candidate, and arbitrary metadata choices do not
automatically produce those targets. This experiment grants no nontrivial
L of genuinely permitted transactions under one fixed authenticated root.

The new useful ingredient is narrowly defined: a large hash-input family of
actual native signatures can be generated after the digest while moving all
per-trial curve work after the hash filter. The unresolved acceptance
criterion is a mandatory native or readable relation on that live hash
which is cheaply satisfiable for exactly the intended outputs, survives a
retaining creator's pre-funding preparation, and preserves a fully charged
honest total below `2^64`. A free h or free recovered K does not meet it.

Reproduce with:

```
python3 research/covenant-2026-09-17/continuation/r12_live_reference.py
```

The executable writes deterministic JSON, uses no nondeterministic RNG,
and changes only files with the `r12_live_reference` prefix. It relies on
the existing R11 lattice and host curve helpers; this is not an independent
reproduction of their full solver proof. No field-arithmetic tests run.
