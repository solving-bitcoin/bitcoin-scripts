# R22: fixed SINGLE selectors and native constant-digest paths

Question: can small native ECDSA networks order a canonical recovery pair,
or turn it into a publicly signable transaction-dependent main key, without
assuming a readable point-arithmetic bridge? Two exact interfaces result:
fixed signatures at the SINGLE constant are finite membership selectors;
variable signatures checked under pairs give an alternating-reciprocal
path equation, subject to explicit native guards. Neither interface yet
supplies the required allowed-output advantage.

This is a specialization and interface audit of
[Search 3's signed-graph algebra](../seven/search3_native_algebra.md), informed
by [R21's canonical-pair analysis](r21_canonical_affine.md). It does not claim
a new canonical-pair primitive or a general impossibility theorem.
[Python](r22_native_relation.py) and [JSON](r22_native_relation.json) are
`locally-reproduced` / `unclassified`. Three prior Core-positive rows are
rechecked algebraically but not executed again. No new Script, transaction,
Core run, library change, or field-library test is supplied. New locking,
witness/hint, stack and opcode measurements are inapplicable.

## Exact native contexts and required guards

Use a legacy P2SH input at index one in a transaction with two inputs and
one output. A signature with effective SINGLE flag has the out-of-range
legacy digest bytes `01` followed by 31 zero bytes, numerical
`C=2^248`. This is independent of outputs and scriptCode. An ALL signature
on the same input has an ordinary digest committing the actual funding
outpoints, processed scriptCode and outputs. The exact arrangement is
already exercised by [R11's funded Core vectors](r11_endomorphism_core.md).

The following source is the canonical unordered pair for an ALL signature
`alpha=(r,s)`, with precisely the nonce roots `R,-R`:

```
K+ = (s/r)R - (z/r)G
K- = -(s/r)R - (z/r)G.
```

The keys must be finite, distinct and canonically compressed; both native
checks must really execute with the same exact signature bytes and context.
The source may be the prior fixed `r=s=1` primitive. Calling it an ALL
signature is an actual-message premise: a literal fixes its flag, whereas
an arbitrary witness signature needs a separate binding.

For each subsequent pair edge, two distinct keys must accept the same
signature `gamma_i=(r_i,s_i)` at actual digest C. A sufficient guard for
antipodality is valid signature length **greater than 57 bytes including
the flag**. If four recovery roots were possible, `r_i<Delta=p-n` and its
positive canonical DER integer would occupy at most 17 bytes; valid `s_i`
occupies at most 33. DER overhead plus the flag is seven bytes, making
57 the maximum. Thus a longer valid signature has only its antipodal pair.
Distinctness alone is insufficient: the fixture retains the known `r=2`
mixed-root counterexample, where both C checks pass but the reflection
formula below fails.

Input position alone does not enforce SINGLE for a free witness signature.
Literal gamma fixes the flag but also fixes the entire finite recovery set.
A computational alternative is the separately investigated
[two-context SINGLE guard](r22_single_guard.md): check the same long gamma
under both distinct keys in two actual same-input CODESEPARATOR contexts.
Complete-pair equality forces equality of the digest scalars. If their
processed scriptCodes have different lengths, ordinary legacy preimages
are different for every non-bug flag; accepting a non-bug alternative then
requires equality modulo n of the distinct native hashes. The SINGLE bug
has C in both contexts. This is a computational guard with a hash
assumption, not an unconditional flag-byte reader. Its concrete program,
processed-preimage check, and costs are the separate report's obligations.

## Fixed C signatures select finitely many digest values

A fixed valid signature gamma at C accepts only its recovery-key set
`A_gamma`, containing at most four finite points. Consequently its check
on a source key is exactly a membership test in that constant set. For any
anchor K in that set, acceptance of either source member requires

```
zG = +sR - rK   or   zG = -sR - rK.
```

Therefore at most `2*|A_gamma| <= 8` digest scalars allow either member to
pass. This counts group points and does not assume their discrete logs are
known. An AND/OR network using a fixed catalogue of M literal C signatures
can distinguish the two source members through these membership outcomes
only on the union of at most `8M` such candidate scalars. Outside that
union every membership predicate returns false on both members. This
statement concerns membership-based selection; it is not a classification
of arbitrary networks containing additional variable signatures or hashes.

For the same fixed numerical signature in the C selector and ALL source,
and with exactly two roots, the candidate group points reduce to

```
CG, CG+2sR, CG-2sR.
```

At `z=C`, both members pass and the selector supplies no ordering. At either
of the other candidate scalars, exactly one member passes, provided the
involved keys are finite. With unknown `log_G(R)`, writing these points
does not provide the scalar z required as a real hash output. With known
nonce scalar 19 and `s=1`, the controls instantiate `z=C,C+38,C-38,C+1`
and obtain respectively two, one, one and zero accepting members. These
four chosen scalars are algebraic controls, not transaction digests.

For `r=s=1` source keys and literal selectors `(1,1)` and `(2,1)` at C, the
fixture enumerates respectively three and eight candidate `zG` points.
It computes the source pair from each of three actual R11 ALL hashes and
checks both selector signatures under each pair: all twelve membership
checks return false. This is not an ordering mechanism for those native
contexts. A signature selected only after the desired native z is known
would have to be committed by the actual program; placing that commitment
in funding changes the outpoint included in z. Leaving the selector freely
replaceable does not establish a fixed reference.

## Variable C edges give an exact native path equation

With the distinctness, antipodality and actual-C premises above, an edge
from K_(i-1) to K_i obeys

```
K_i = -K_(i-1) - (2C/r_i)G.
```

This follows directly by adding the two ECDSA equations for opposite nonce
points. It can be enforced with two CHECKSIG checks on the same signature
and the two keys; a correctly constrained duplicated-signature 2-of-2
CHECKMULTISIG can express the same pair acceptance. A general k-of-n
multisig must not be assumed to check a particular two-key edge.

For an m-edge path define the publicly computable scalar

```
S_m = sum_{i=1..m} (-1)^(m-i)/r_i.
```

Composition gives the exact endpoint relation

```
K_m = (-1)^m K_0 - 2C*S_m*G.
```

Now let the endpoints be the two ALL source members K+ and K-.

| Path length | Necessary consequence |
|---|---|
| odd m | `z/r = C*S_m mod n` |
| even m | `log_G(R) = C*r*S_m/s mod n`, with the sign of R fixed by the first source key |

In particular, three C edges give
`z/r=C*(1/r_1-1/r_2+1/r_3)`. Reversing an odd path leaves S_m unchanged,
so this endpoint scalar relation does not select an orientation of the
source pair. Individual nonce-root and signature constraints still apply;
this observation does not identify all possible witnesses of the path.

Two C edges give the explicit extractor
`log_G(R)=C*r*(1/r_2-1/r_1)/s`. It is an extractor from **the complete valid
ECDSA graph**, not an assertion that a lone Schnorr signature reveals a
private key. A construction can deliberately choose a known-log R; the
extractor is not a proof against that option.

Every vertex reachable from K+ through these edges has the form

```
K_j = (-1)^j (s/r)R + b_j*G,
```

where b_j is computable from z and the edge r values. Its R coefficient
never vanishes. Supplying an actual private scalar for any such vertex
therefore supplies `log_G(R)` as well. Conversely, when R's logarithm is
public, all those vertex scalars are public. Choosing one of these vertices
as a main verification key has not by itself created a secretless output
restriction. This does not rule out producing a signature by another method
without first computing that key scalar, or using a different native operation.

The reciprocal relation is not a free scalar-arithmetic gate. Each r_i must
be the x-coordinate modulo n of an actual nonce point, with an s_i that makes
both native signatures verify. Assigning convenient scalar denominators
satisfying the displayed sum does not supply those nonce logarithms or valid
signatures. Mixed pairs from four-root signatures, changing source scalars,
and different operations remain outside this antipodal-edge classification.

## Deterministic controls and retained-state comparison

The new host fixture includes:

- Three prior actual C/ALL positive rows from R11. It recomputes each actual
  ALL hash, verifies the four ECDSA equations, checks both recovery sets are
  antipodal, and confirms the one-edge equation `z/r_ALL=C/r_C`.
- The twelve fixed-selector checks and four explicit positive/negative
  selector controls described above.
- Constructed paths of one, two and three C edges, using public starting
  scalar 7 and nonces 11, 13 and 17. All six edge instances have signatures
  longer than 57 bytes and verify under both endpoints, giving twelve C
  equations. Each path is closed with an ALL-signature equation using
  known nonce scalar 19, giving six source equations. The closing z values
  are manufactured scalars, explicitly not native transaction hashes.
  The even path recovers the exact source nonce scalar; both odd paths pass
  their reciprocal equation and reversal check.
- A mixed four-root edge that passes both signatures but fails reflection,
  plus the exact 57-byte DER bound.

The original R11 Core results already supply the retained-state comparison
for the freely chosen one-edge interface: the same funding and locking
program accepts recomputed public witnesses for different recipients and
amounts. Merely replaying an old witness fails, but fresh witnesses pass.
R22 does not relabel that result as a new counterexample or extrapolate it
to every larger graph. The manufactured longer paths are equation controls,
not a demonstrated cheap solver for arbitrary actual z.

A useful continuation would supply a natively guarded C graph and an honest
nonce/signature construction for the **actual** funded ALL digest, then
bind a fixed allowed-output reference that is not replaced when witnesses
are recomputed. It must show the asymmetry with all setup state retained.
The fixed-selector candidate set, the even-path extractor, and the odd-path
reciprocal equation give explicit acceptance tests for such a proposal.
No graph meeting the complete criterion is obtained here.

Reproduce: `python3 research/covenant-2026-09-17/continuation/r22_native_relation.py`.
