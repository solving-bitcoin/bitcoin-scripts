# Exact extraction from publicly related ECDSA nonces

Question: can the existing anchored and direct point-lock extractors recover
more accepted scalar openings without adding checks or bytes onchain?
The comparison objective is the set of transcripts covered by an exact
extraction argument, not a higher heuristic security estimate.

The extractors now handle nondegenerate, publicly known affine relations
between two reconstructed nonce points. Their default search includes the
six signed secp256k1 endomorphisms. Thus distinct r values do not by themselves
put a transcript outside extraction. General unrelated nonces remain open,
and an explicit degenerate control shows why a detected relation alone is
insufficient.

[Shared extractor and focused tests](nonce_relation_extraction.py),
[anchored wrapper](anchored_extraction.py),
[direct wrapper](direct_context_extraction.py), and
[test report with source hashes](nonce-relation-extraction.json).

## Exact equation

Let P=dG be the verified ECDSA key, n the group order and p the field prime.
For two valid signature/digest triples
(r_i,s_i,z_i) and (r_j,s_j,z_j), reconstruct the actual verification points

```
R_i = (z_i G + r_i P) / s_i,
R_j = (z_j G + r_j P) / s_j.
```

Suppose known public scalars a != 0 and b satisfy R_j=a R_i+bG. The extractor
checks that point equation; it does not accept a claimed relation as a hint.
Substitution and multiplication by s_i give

```
(a*s_j*r_i - s_i*r_j) P
    = (s_i*z_j - a*s_j*z_i - b*s_i*s_j) G.
```

Write D=a*s_j*r_i-s_i*r_j and U=s_i*z_j-a*s_j*z_i-b*s_i*s_j, all modulo n.
If D != 0, the scalar is exactly d=U/D mod n. The implementation verifies
dG=P before returning. No nonce scalar, private setup state, nonce-search
assumption or random-oracle assumption is needed for this implication.
The digests may differ and the signatures may use different raw sighash
bytes: the caller must derive each actual native digest from its transaction
and executed script context.

For the anchored predicate, its verified fixed signature (r_T,1) then gives
the target scalar t=+/-(r_T*d+z_0); the existing wrapper chooses the sign by
checking tG=T. The direct predicate returns d itself. This adds a fallback
after their existing G/2 and repeated-nonce branches, preserving those APIs
apart from an optional keyword for an explicit relation list.

The anchored wrapper now includes the fixed anchor itself in the relation
search. Its rows are `(r_T,1,z_0)` followed by the short checks; returned pair
indices use this order, with anchor index zero. Consequently a short nonce
related to the actual anchor nonce `+/-T` can extract even when no pair of
short nonces is related. The wrapper checks the reconstructed anchor sign;
it does not presume the target's stored sign is the signature nonce sign.
For anchor index i and a short check j the formula specializes to
`d=(z_j-a*s_j*z_0-b*s_j)/(a*s_j*r_T-r_j)` when its denominator is nonzero.
This extension changes no onchain predicate or data.

## Default relation search

For secp256k1, choose the paired constants beta and lambda with

```
phi(x,y) = (beta*x mod p, y),       phi(G) = lambda*G,
beta^3 = 1 mod p,                 lambda^3 = 1 mod n.
```

The implementation checks the pairing on G and tests a=+/-lambda^j for
j=0,1,2 with b=0. The coordinate endomorphism makes these tests cheap after
nonce reconstruction. This uses multiplication modulo the correct field for
coordinates and the correct group order for scalars; it does not assume an
incorrect linear identity between their x-coordinates modulo n.

A caller can supply additional public (a,b) pairs, for example to cover a
documented translated nonce family. There is no unbounded scan over a or b,
and discovering an arbitrary hidden affine relation is not claimed. Every
two group points have some scalar relation; that fact alone is not an
efficient extraction algorithm. Negative or high-S nonce signs must also
negate b when appropriate.

## Degeneracy is a real boundary

When D=0, the verified equations force U=0. They give no invertible scalar
equation. The extractor reports unresolved rather than dividing by zero or
claiming that the key is now known.

The test constructs such a case without computing a discrete logarithm.
Transparently lift a hash-derived x-coordinate to an unknown-log point X.
Choose public nonzero u and public v, and let

```
P = u X + v G,
R_i = a_i X + b_i G,
r_i = x(R_i) mod n,
s_i = r_i*u/a_i,
z_i = s_i*b_i-r_i*v.
```

Each row verifies since s_i R_i=z_iG+r_iP. The nonce relation is public, but
its extraction determinant is zero. Recovering d would also recover
log_G(X)=(d-v)/u. The reproduction uses (a_i,b_i)=(1,0) and (lambda,17).

This control uses unrestricted-length ECDSA rows and deliberately assigned
digests. It is **not** a native cap60 point-lock counterexample, an actual
Bitcoin hash preimage, or a new lower bound. It establishes the helper's
necessary refusal case and prevents extending the positive theorem beyond
its nonzero-determinant condition.

## Reproduction and scope

Seven focused test methods pass. They include:

- All six signed endomorphisms through both wrappers, for 12 wrapper cases.
  Four multipliers give distinct r values in five-check, exact-60-byte
  anchored fixtures; the other two exercise existing repeated-nonce behavior.
- Four translated relations through both wrappers, for eight positive cases.
  The default relation set deliberately leaves those fixtures unresolved;
  explicitly supplying the public relation enables extraction.
- Twelve anchor-only cases: both reconstructed anchor signs and all six
  signed endomorphisms, each with five exact-60-byte short checks. The
  short-only helper first returns unresolved; including the anchor extracts.
- The zero-determinant construction above; high-S sign handling; reduced
  digest boundaries 0 and n-1; six invalid ECDSA rows; invalid points and a
  zero multiplier; and six unrelated short nonces that remain unresolved.

The existing six anchored and five direct extraction regressions also pass:
**18 test methods total**, with no tests of unrelated primitives or field
arithmetic modules. The short-signature fixtures choose their digest scalars
algebraically. No fresh Bitcoin transaction or Core run is claimed. Source
hashes in older native reports remain historical; those reports are not
silently regenerated by this extractor change.

Incremental onchain script bytes, witness bytes, opcodes, hint items and
stack items are all zero. This offchain helper has no Bitcoin stack or
validation budget. The existing anchored/direct full fixtures retain four
hints, 33 entry data items and 34 complete witness items per input, all hints
present at entry; across 115 independent inputs this is 460 hints and 3,795
entry items. Their respective combined main-plus-alt-stack peaks remain
85 and 83. This helper does not invoke the tapscript/unlimited-stack runner.

Evidence: **locally-reproduced** for the tests and implementation;
**inspected** for the algebraic implication. Deployment: **unclassified** for
this extraction research. No new native or complete-protocol deployment claim
is inherited from the historical fixtures.

The [cross-key follow-up](cross-key-nonce-extraction.md) combines rows across
different labels and extracts nondegenerate graph cycles missed by separate
per-key checks. Its synthetic rank-deficient control and native replay keep
the same distinction between exact covered cases and general extraction.

The alternative-nonce cost model already requires unrelated private nonces;
its numerical work estimates do not improve merely because this branch now
exists. All-consensus extraction for the remaining transcripts, public
garbling/translation binding and the full setup/transaction requirements of
the sub-100,000-vB goal remain unresolved.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/nonce_relation_extraction.py -v
cd research/pointlocks-2026-09-17
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v anchored_extraction direct_context_extraction
```
