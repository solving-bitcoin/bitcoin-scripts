# Publicly checked vector labels: a working gate and its delivery cost

Question: can a purely algebraic, publicly checked gate preserve access to
only one complete input-label vector, overcoming the scalar AND failure?
The comparison counts secret coordinates that point locks would have to
deliver, not just the size of public offchain tables.

**Yes at the single-gate boundary, using two scalars per input label.** Four
public point equations certify evaluation for every input, including a
maliciously generated setup. Under independent honest masks and the secp256k1
discrete-log assumption, one opening does not reveal a complete alternative
input label or the opposite output label. There is no encrypted table or ZKP.
The direct scalar-opening interface is too expensive with the existing exact
legacy locks; no complete publication construction is claimed.

[Executable reference](vector_label_gate_probe.py),
[deterministic report](vector-label-gate.json),
[single-scalar boundary](../../knowledge/negative-results/scalar-label-linear-gates.md).

## Construction and public check

The later [shared-coordinate construction](shared-vector-gates.md) reduces
the distinct scalar opening count from four to three and attains the minimum
worst-case rank for the stated linear AND interface. The measurements and
four-coordinate reference in this report remain historical. Its direct
legacy cost is still above the goal, and high-rate full-subset pools cannot
inherit this complement lookup merely by correlating their scalar labels.

Work modulo the secp256k1 group order n. For a publicly specified binary
function f, choose independent secret scalars c0, c1 and r00, r01, r10, r11.
The two output labels are c0 and c1. Input labels are vectors:

```
L0 = (r00, r01)       L1 = (r10, r11)
R0 = (c[f(0,0)]-r00, c[f(1,0)]-r10)
R1 = (c[f(0,1)]-r01, c[f(1,1)]-r11).
```

Publish generator multiples of all ten scalar coordinates. The public
checker takes the intended f from the caller, validates finite curve points
and distinct label alternatives, and checks, for all a,b in {0,1},

```
point(L_a[b]) + point(R_b[a]) = point(c[f(a,b)]).
```

An opening supplies both coordinates of L_a and R_b. After checking each
against its committed point, output `L_a[b]+R_b[a] mod n`. Injectivity of
scalar multiplication makes each public equation an exact scalar equation.
Consequently an accepted setup reconstructs the committed output label for
every valid full opening. A correct garbling of OR is rejected when the
caller requested AND; the creator cannot redefine the intended function.

All coordinates are canonical scalars. The reference rejects infinity and
zero-coordinate openings and resamples the negligible degenerate honest
setups. No secret values are arguments to the public checker. The fixture
seeds are public test material, not production entropy.

## Why the alternative complete labels remain hidden

Represent every scalar as a linear form in
`u=(c0,c1,r00,r01,r10,r11)`. For any of the four messages the disclosed four
forms have rank four. Their span contains the selected output form but not
the opposite one. Adding the complete labels of any different message
increases rank by at least one. These facts hold for all 16 Boolean truth
tables, not just AND. Some *individual coordinates* can become known;
neither full alternative label nor an alternative complete input does.

The public curve commitments require a computational argument. For any
unspanned target form l, let A be the disclosed-form matrix. Choose h with
`A*h=0` and `l*h=1`. Given a discrete-log challenge X=xG, choose known uniform
u0 and construct every public point as

```
point(q) = (q*u0)G + (q*h)X.
```

This commits to `u=u0+h*x`, a uniform secret vector. All requested opening
scalars are `A*u0`, computable without x. Recovering the target scalar gives
`x = l*u - l*u0`. Thus a recovery of an unspanned coordinate solves a
discrete logarithm. For an adversary choosing its input and alternative,
guessing among the fixed finite possibilities incurs a constant reduction
loss. Rejection of degenerate honest points changes the uniform distribution
only negligibly. The probe exercises 12 challenge embeddings using a
simulator whose arguments include X but never x.

This is a one-gate, one-opening statement. It is not a proof for arbitrary
fanout, shared masks, repeated openings or an assembled BitVM3 verifier.
Scalar-linear rank checks alone are not information-theoretic secrecy in
the presence of public points. Component hiding relies on ECDLP; generic
single-target work for this curve is of order 2^128 before concrete losses
and multi-target effects. No end-to-end security level is inherited by the
98,323-vB candidate.

Public checking certifies algebraic consistency, not secret entropy. A
creator can deliberately reveal secrets it knows; the hiding claim assumes
private independent generation and no such extra disclosure. Keeping the
creator's secrets does not affect the checked reconstruction equations.

## The cost is in the labels

Per gate there are ten compressed points (330 raw bytes), four point-sum
checks, two selected input labels with four total scalars (128 raw bytes),
and one output scalar. Framing and function identification are additional.
These are host-side payload counts, not Bitcoin witness or vbyte metrics.

Each input label's two forms have rank two. One extracted scalar plus public
affine operations cannot reconstruct both independent coordinates. Applying
this direct interface to 1,024 independent gates on 2,048 message bits would
require 4,096 scalar openings. Even granting an efficient native wrapper,
the guarded legacy sum-key representation costs at least

```
4096 * (58-byte signature + 1-byte push) = 241,664 legacy vB
```

before all keys, checks, funding, inputs, outputs and authorization. This is
a bound on that direct wrapper, not on witness-discounted alternatives or
all algebraic garbling. The existing locks also cannot be assumed to accept
arbitrarily prescribed scalar labels with efficient setup.

Componentwise composition of this particular gate doubles the label length
at each gate on a path when its output must supply a vector to the next gate.
A literal depth-d tree expansion therefore has 2^d coordinates per leaf.
This is an algebraic size recurrence, not an implemented full circuit or a
lower bound on more advanced gate-evaluation secret sharing.

## Packing is a separate binding obligation

The public identity `T=A+2^128*B` does not certify that the scalar coordinates
of A and B are each 128-bit integers. For small positive a,b, the tuples

```
(a,b) and (a+2^128,b-1)
```

have exactly the same packed scalar and point. The second tuple has an
out-of-range first coordinate. Our control makes this change to L0, updates
the corresponding right-label commitments, and passes every gate equation
and the packing point equation. Unpacking the unchanged scalar returns the
old tuple, which fails the new prebound label checks. This is a public-setup
counterexample to unverified digit packing, not a native Bitcoin spend.
No range proof or scalar-packing mechanism is supplied by this experiment.

## Evidence and relation to prior work

Nine focused tests cover 16 curve instances and 64 input evaluations, all
192 alternative complete-input span checks, 64 opposite-output checks,
12 public challenge embeddings, ten changed point commitments, malformed
encodings/openings, wrong-function rejection and the packing counterexample.
An exhaustive projective-line screen over F_2^3 and F_3^3 finds 168 and
5,616 scalar-label assignments satisfying the input-span restriction; none
supports a hidden scalar-linear AND zero-output label. The accompanying
proof covers arbitrary fields; these screens are corroboration, not the proof.

[Kolesnikov, ASIACRYPT 2005, LNCS 3788, pp. 136–155](https://www.cs.toronto.edu/~vlad/papers/GESS_AC05Proceedings.pdf)
provides the gate-evaluation secret-sharing framework and more efficient
formula constructions in a semi-honest OT setting. This local symmetric
row-sharing gadget is not an implementation of the paper's optimized
construction or its complete protocol. The stronger restriction on access
to alternative complete message labels is checked separately here. No
optimality or novelty claim is made.

Evidence: **locally-reproduced** curve/vector controls and **inspected**
algebraic arguments and source boundary. Deployment: **unclassified**.
There is no Script, witness, hint stack, opcode/validation budget, transaction,
Core run or setup benchmark; their metrics are not applicable, not zero.
No existing native candidate, timing artifact or public primitive API changes.

A useful next construction must deliver these or other publicly checked
labels through actual point-lock openings within the byte budget, or give
a nonlinear compression whose public binding and one-opening restriction
survive composition. All native extraction, full-verifier and setup criteria
of the original goal still apply.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/vector_label_gate_probe.py -v
```
