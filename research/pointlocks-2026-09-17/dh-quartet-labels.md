# One scalar opening selects two Diffie–Hellman point labels

Question: can secret **group elements**, computed from a native scalar
opening, deliver more message bits than the previous scalar-label interface?

**At the offchain label boundary, one of four scalar openings selects two
fixed binary point labels.** The labels are group elements, not their scalar
logs. The correlated version publicly checks its input relations and excludes
all exact output-label collisions. This is not yet a complete publication:
binding to an actual garbled verifier and its full setup measurement remain
absent. A [native follow-up](fixed-digest-nonce.md) now supplies small legacy
openings, but its explicit key tables exceed the full onchain budget.
A shape-only independent version also has a
chosen-setup label-alias counterexample.

[Implementation](dh_quartet_label_probe.py),
[deterministic report](dh-quartet-label.json),
[subset boundary](../../knowledge/negative-results/quadratic-dh-subset-labels.md).

## Four choices, two bits

Commit four nonzero input scalars through distinct points X_i=x_i*G. Define
the following **secret** point labels; the computed values are not published:

| Message wire | Label for zero | Label for one |
| --- | --- | --- |
| First bit | L00=x0*x1*G | L01=x2*x3*G |
| Second bit | L10=x0*x2*G | L11=x1*x3*G |

Index i represents the two-bit binary encoding of i. Opening x_i computes
each required label by multiplying a public point by x_i:

| Opened index | Message | First point label | Second point label |
| --- | --- | --- | --- |
| 0 | 00 | x0*X1 | x0*X2 |
| 1 | 01 | x1*X0 | x1*X3 |
| 2 | 10 | x2*X3 | x2*X0 |
| 3 | 11 | x3*X2 | x3*X1 |

The evaluator checks the canonical indexed opening against X_i. The table
is fixed by the implementation, not supplied by an untrusted setup. Thus
the public inputs mathematically fix every label, and every accepted scalar
opening reconstructs the corresponding group elements. No ciphertext or
separate claimed label hash occurs in this construction.

For independent uniformly generated inputs, either opposite label is a
CDH value on two unopened independent points. Embed a CDH challenge in those
two input positions and generate the other scalars normally. The selected
opening and both selected labels remain simulatable. A correct opposite
label solves that challenge. Each different complete two-bit codeword needs
at least one such opposite component. These are one-opening arguments;
multiple openings of a quartet are not supported. Public deterministic
fixtures are tests, not private production entropy.

## Two independent setup scalars suffice

A correlated variant sets

```
x0=a,  x1=b,  x2=a+b,  x3=a-b mod n.
X0=A,  X1=B,  X2=A+B,  X3=A-B.
```

Its public checker verifies these point equations, finite distinct input
points, and the separation test below. The four label polynomials become

```
q00=ab,  q01=a^2-b^2,  q10=a^2+ab,  q11=ab-b^2.
```

Conditioned on one scalar opening, write `(a,b)=u+h*z`, where h annihilates
the opened form. For every opposite label,

```
L_opposite = q0*G + q1*(zG) + q2*(z^2 G),  q2 != 0.
```

The eight q2 coefficients in index/bit order are
`[-1,-1,1,1,-1,-2,1,2]`. From an opposite point, subtract the known first
two terms and multiply by q2 inverse to obtain the square-CDH challenge
answer z^2 G. Three square-CDH answers compute ordinary CDH by polarization:
`uvG = ((u+v)^2G-u^2G-v^2G)/2`. The test embeds only the challenge point;
its scalar is used separately by the test oracle to verify the result.

This argument assumes independently private random a,b and one opening.
Known affine input correlations here do not alone reveal the alternatives.
It does not certify the entropy of a creator-selected setup, protect against
deliberate extra disclosures, or prove security of an added ciphertext layer.

## Publicly excluding exact point-label aliases

Input points being distinct is insufficient in the independent profile.
Choose private nonzero a,b,c and set inputs to `(a,b,c,ab/c)`. Its point-only
shape check passes, but L00=L01. The complete point-label vectors for messages
00 and 10 are identical. The original scalar opening already gives that
alternative vector; no additional scalar is needed. The native index still
decodes uniquely, so this is label aliasing, not ambiguous index decoding.
This host example is not a Bitcoin transaction counterexample.

For the correlated profile, all six pairwise output differences can be
checked without revealing the labels. Four factor through nonzero a, b,
a+b or a-b. The difference `ab-(a^2-b^2)` has discriminant 5, which is a
quadratic nonresidue modulo the secp256k1 order n, so it cannot vanish for
nonzero b. The remaining difference is `a^2+b^2`.

Since n=1 mod 4, compute a public i with i^2=-1 mod n. Reject if

```
A = i*B  or  A = -i*B.
```

These point checks exclude the remaining equality. Thus all four implicit
point labels are pairwise distinct for **every accepted correlated setup**,
not only random samples. The reference derives i from the first quadratic
nonresidue and checks the facts about n; this is public field arithmetic,
not a ZKP. Two deliberately colliding correlated setups are rejected.

This separation guarantee has a precise scope. It excludes equality, not
every efficiently known relation between labels or every weak choice of
secrets. The checker still does not inspect a downstream garbled circuit.

## Cost boundary and unresolved composition

One quartet requires one 32-byte scalar opening and yields two point-valued
labels, using two variable-base scalar multiplications after opening checks.
Four public input point slots are stored; the correlated profile derives them
from two independent scalar commitments. Those counts are host data, not
Bitcoin witness metrics or permission to omit candidate keys from Script.

As an abstract alphabet, 1,024 independent quartets cover all 2^2048 future
messages. Granting an efficient guarded legacy scalar wrapper with 58-byte
signatures, the signature pushes alone would cost **60,416 vB**. This is a
partial lower cost, not a sub-100,000-vB transaction. Candidate keys, scripts,
selection, output creation and consumption, authorization and framing are
all excluded. The subsequent [fixed-digest nonce wrapper](fixed-digest-nonce.md)
does deliver these correlated scalars. Its 199-byte quartet script and four
explicit candidate keys exceed the budget when repeated 1,024 times; the
60,416-vB signature-only floor is therefore not a full-cost estimate.

The earlier scalar-linear and ratio results do not apply to these outputs:
the evaluator obtains x_i*x_j*G, **not x_i*x_j**. These points could serve as
offchain key material for a different verifier interface. They do not replace
the goal's requirement to extract the scalars of the native locked points.

Three unresolved obligations prevent treating the component as a solution:

- Bind actual garbling entries to these implicit point labels and the intended
  function using a public check. Hashing a label or accepting a supplied hash
  does not establish that binding. The test changes a proposed downstream
  label hash while the input checker continues to pass.
- Compose gates with this interface. A secret point is not a scalar that can
  multiply another point at the next gate. The reference claims a two-bit
  selector, not arbitrary circuit garbling.
- Improve on the native wrapper's explicit-table cost and measure every
  transaction and the whole setup. The independent version's shape check
  also does not establish malicious
  setup label separation; the correlated version repairs exact equalities
  only.

The [graph boundary](../../knowledge/negative-results/quadratic-dh-subset-labels.md)
further shows that independent-coordinate DH label vectors cannot directly
classify the full 5-of-54 alphabet into two protected labels. Missing three
coordinates admits a positive construction; missing four or more does not
in that model. Correlated inputs, additional nonlinear metadata and other
group-valued constructions require separate analysis.

The subsequent [correlated degree argument](correlated-quadratic-labels.md)
now covers correlations that preserve every unselected scalar against every
t-subset. The missing-three boundary survives for quadratic point labels:
at 5-of-54, a covering product would need degree at least 50 rather than four.
Restricted choice families and additional nonlinear metadata remain outside
that follow-up as well.

## Evidence and reproduction

Twelve focused tests cover 32 honest evaluations, eight CDH and eight
square-CDH embeddings, the polarization identity, twelve alternative-codeword
component checks, altered input points, nine malformed openings,
chosen-setup collision controls and the public-hash-binding boundary. Six graph
screens enumerate all nonempty DH-edge vectors through six input coordinates;
four larger majority examples corroborate the missing-triple construction.

Evidence: **locally-reproduced** tests and **inspected** algebra. Deployment:
**unclassified** for this host experiment. Its historical report includes no
Bitcoin execution, native scalar wrapper, complete verifier or setup benchmark;
the native follow-up has separate artifacts. Script/witness bytes, hint and entry
items, combined stack peak, opcodes, validation budget and full onchain vbytes
are N/A. Existing native artifacts and their 98,323-vB measurement are unchanged.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/dh_quartet_label_probe.py -v
```
