# Four recovery keys: exact extraction with inadequate hiding

Can all four ECDSA public-key recovery candidates replace the short-signature
assumption? They yield an exact extraction equation, but cheap constant-digest
setup confines the label to an interval-DLP instance of about128 bits. This is
not an equivalent-security replacement for the existing constructions.

## Extraction

Fix four distinct valid curve points P_i and nonzero target T=sum(P_i).
Require the same ECDSA signature (r,s) under every P_i at the same actual
reduced digest z. Public setup checks distinct points, not just distinct byte
encodings. Each verification reconstructs R_i=(zG+rP_i)/s.

Since r,s are nonzero, the four R_i are distinct. Every x(R_i) mod n equals r.
The secp256k1 base-field prime p is below2n, so the only possible coordinates
are r and r+n, each having at most two opposite curve points. Four successful
checks must therefore use the full set R,-R,U,-U, whose sum is zero. Thus

    4zG+rT=0,   t=-4z/r mod n.

This works at every common digest, without a signature-size assumption or
knowledge of nonce scalars. It is an algebraic theorem, not a native fixture.

## Cheap setup and its limitation

Choose0<r<p-n with both r and r+n lifting to the curve. Set s=1 and use the
legacy SIGHASH_SINGLE constant C=2^248. For each of the four nonce points R_i,
set P_i=(R_i-CG)/r. The signature (r,1,SINGLE) verifies under every key and
t=-4C/r. Setup uses square roots and group arithmetic without nonce DLPs.
This constant digest is a legacy property, not a P2WSH construction.

[Source](four_recovery_key_probe.py) and
[five deterministic fixtures](four_recovery_key_probe.json) reproduce all20
ECDSA checks and target-scalar equations. Their signatures are25 bytes.
No Script, transaction, stack metric or Core verdict is claimed. Evidence:
**locally-reproduced** curve algebra; deployment: **unclassified**.

Every honestly generated target satisfies

    rT=-4CG,   0<r<p-n.

An observer can recover r by an interval discrete-log search using base T
and target -4CG, then compute t. Here log2(p-n)=128.345702, so the generic
square-root search scale is approximately2^64.17 group operations, before
method-dependent constants. This is analysis, not an executed attack; see
[Galbraith, Pollard and Ruprai, Computing discrete logarithms in an interval](https://eprint.iacr.org/2010/617.pdf)
for interval-DLP algorithms and their assumptions.

Cheap25-byte signatures therefore weaken label hiding substantially. Full-size
public keys do not restore128-bit hiding. Four bound keys per label also add
authentication cost; no compact shared-key alphabet is supplied here. A native
setup avoiding the restricted label space and funding self-reference would
require a different construction.

A [fixed-root-orbit follow-up](four-root-orbit.md) changes the hidden label to
a full scalar multiplying all four fixed roots. Its canonical scalar is
uniquely bound at the constant digest, so the interval weakness of this
inverse-r sum label does not carry over. Explicit four-key legacy tables
still exceed100,000 vB under the follow-up's optimistic representation bound.
No new native execution or complete solution follows.
