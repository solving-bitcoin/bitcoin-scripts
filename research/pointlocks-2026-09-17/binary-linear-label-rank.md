# Direct linear delivery needs one field opening per message bit

Question: can correlated scalar labels replace the nonlinear translation of
460 point openings into the 2,048 binary inputs of the message verifier?
The objective is a publicly checkable algebraic bridge that reduces total
publication cost without exposing labels for another message.

For a **direct scalar-linear binary-label interface**, the answer is no:
every complete assignment's selected labels must be linearly independent.
Delivering k such labels from t field-element openings therefore requires
t >= k. The argument does not assume independently sampled labels or a
common free-XOR offset. It applies to the full message cube, not automatically
to the restricted per-pool rank alphabet.

This is a scoped lower bound, not an impossibility result for the goal.
The existing nonlinear garbled decoder and PRF/DH translations are outside
this model. A different authenticated input interface can also escape it.

[Executable examples](binary_linear_label_rank.py) and
[results and provenance](binary-linear-label-rank.json).

## Model

Work over a field F. Represent the hidden scalar values by a vector X.
After quotienting out scalar-linear information already public at setup,
let ell_i^0 and ell_i^1 be public coefficient vectors defining the two secret
label preimages for message bit i. Known affine constants can be subtracted.
Curve commitments to these scalars are not their discrete logarithms.

The interface has these requirements:

1. All 2^k binary messages are admissible after the same setup. Each message
   m supplies the selected value <ell_i^(m_i),X> for every bit i.
2. A publication may not expose the opposite label at any bit. With all other
   labels unchanged, that would give the complete binary-label vector for
   the other admissible message obtained by flipping that bit. This assumes
   these binary labels are the complete message-authentication interface;
   an additional message-dependent secret authentication input is outside
   this model.
3. The t revealed field elements are linear forms v_j in X. Every selected
   label is reconstructed by a public linear combination of these openings.
   Coefficients can depend on the public setup and message/selected indices;
   secret-value-dependent multiplication or inversion is not linear decoding.

Hashing a linearly recovered preimage into a fixed-width garbled label does
not repair an opposite-preimage disclosure: the recipient can hash it too.
The theorem does not treat an arbitrary nonlinear KDF expansion as a linear
map over F. Nor does it equate one secp256k1 scalar with one element of every
other field or with one secret bit.

## Proof

Fix any message m. Suppose its selected vectors are dependent. Then for some
j there are public coefficients c_i such that

```
ell_j^(m_j) = sum_{i != j} c_i * ell_i^(m_i).
```

Consider the valid message m' that flips only bit j. Its opening still
supplies every value on the right-hand side, since the other bits did not
change. It also supplies ell_j^(1-m_j). The recipient can therefore recover
both labels for bit j and assemble the label vectors for m' and m. This
violates the required one-message access property.

Hence the k selected vectors are independent for every m. Linear decoding
puts all k inside span(v_1,...,v_t), which has dimension at most t. Therefore
t >= k. There must also be at least k+1 hidden dimensions in the quotient,
since the opposite label must lie outside the selected k-dimensional span.

This proof uses privacy as well as correctness. Merely checking that fewer
public observations distinguish all message bit strings would not prove that
they deliver all the required secret labels.

## Tight boundary and a concrete failure

The algebraic bound is tight. With independent hidden field values
A_0,...,A_(k-1),Delta, define

```
L_i^b = A_i + b*Delta.
```

For every message the k selected forms are independent, and every opposite
form lies outside their span. Releasing those k scalars gives the direct
linear interface. This is an algebraic access-structure example, not a
claim that addition modulo n implements free XOR or supplies a publicly
verified garbling.

Correlating A_2=A_0+A_1 instead reduces the all-zero assignment's rank to two.
An opening of message 001 provides

```
A_0, A_1, A_0+A_1+Delta.
```

The recipient computes the zero label of bit 2 as A_0+A_1 and can also
assemble message 000's labels. With this common additive offset it additionally
learns Delta and all six labels. The implementation reproduces the calculation
using selected scalars only, checks the recovered scalars against actual
secp256k1 point commitments, and checks a SHA256-derived opposite label.
All numerical secrets are deterministic public test fixtures.

The more general dependent-vector examples use independent one-labels, not
a common Delta. They still permit the single-bit message change. The theorem
therefore does not depend on the global-offset leak from the earlier
public-zero-label counterexample.

## Restricted onchain consequence

Suppose the native wrapper is the existing legacy sum-key family, each
signature supplies one scalar opening to the direct linear decoder, and the
binary labels are the complete authenticated message interface. At k=2,048,
there must be at least 2,048 independent scalar openings.

The guard requires a signature item longer than 57 bytes. Even granting a
58-byte signature for every opening, its direct Script push takes 59 bytes.
Legacy scriptSig bytes have no witness discount. The signatures alone cost

```
2048 * 59 = 120,832 vB.
```

Every key, selector, verifier, input/output and transaction header is granted
for free in this lower bound. It already exceeds 100,000 vB. This is an
analytic bound for the stated wrapper/translation combination, not a new
serialized transaction measurement. It does not cover a different native
mechanism supplying several independent openings per signature, a SegWit
construction, or a nonlinear translation.

The current 460-scalar complement experiment avoids this direct-linear
model by encrypted share recovery and nonlinear garbled rank/message
evaluation. The result does not invalidate that honest computation. It rules
out replacing it merely with public linear interpolation into the same 2,048
binary label preimages. Public binding of the actual nonlinear translation
remains a separate open problem.

## Reproduction and next direction

The exact vector tests enumerate 510 messages for k=1,...,8 at the tight
boundary and check 3,586 opposite-label exclusions. Seven dependent examples
for k=2,...,8 reproduce the bit-flip disclosure without any common offset.
The separate secp256k1/KDF fixture checks the correlated three-bit example.
Rational vector tests are finite regression evidence; the field-independent
argument above is the proof.

Evidence: **inspected** proof and restricted cost implication;
**locally-reproduced** exact examples and point/KDF checks. Deployment:
**unclassified**. No Script, Core execution, setup benchmark or full garbling
is performed. There is no new Bitcoin witness, hint count or stack peak to
measure; existing onchain artifacts and their resource counts are unchanged.

A viable next construction must provide publicly bound nonlinear label
delivery, change the authenticated input interface, or supply a different
native aggregate-opening primitive. Additional linear correlation among
ordinary binary label scalars does not close this particular route.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/binary_linear_label_rank.py
```
