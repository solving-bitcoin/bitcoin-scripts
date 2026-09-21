# Publicly checked algebraic gates do not automatically bind one message

Question: can a garbling made only of publicly checkable scalar/point
relations replace the encrypted label translator, avoiding the unresolved
malicious-table check? The tested AND gate has an exact public correctness
check, but fails the required restriction to one message's input labels.
Making all six point commitments distinct does not repair it.

[Executable experiment](public_algebraic_gate_probe.py),
[test report](public-algebraic-gate.json),
[pinned source review](privacy-free-formula-source.json).

## Exact positive property

Work over the secp256k1 scalar field. Choose secret scalars k0, u, v and
public offsets a,b. Assign the following scalar labels and publish their
generator multiples:

```
left0  = k0+a       right0 = k0+b       output0 = k0
left1  = u          right1 = v          output1 = u+v.
```

Every observer can check the corresponding three point equations. The
setup check receives no scalar labels or garbling seed. Injectivity of
scalar multiplication modulo the group order makes the checked equalities
binding. An opening for input 01 computes output0=left0-a, input 10 computes
output0=right0-b, and input 11 computes output1=left1+right1. Input 00 works
through either zero input. All output scalars can be checked against their
precommitted output points. This is a correct algebraic AND gadget.

## Failure of the required input-label property

From an authorized 01 opening the receiver knows left0 and right1. It can
also compute

```
k0     = left0-a
right0 = k0+b.
```

It now has the complete valid label pair for the different message 00.
Likewise, 10 exposes left0 and permits 00. The receiver uses only the public
setup and the two released labels; the reproduction passes no hidden state
to this calculation. The alternative labels match the original committed
points and pass the same evaluator's input checks.

For a=b=0 this follows from shared zero labels. Fresh public offsets can
make every point distinct, yet both affine maps remain invertible and the
same recovery applies. This defeats the proposed distinct-point repair
without solving any discrete logarithm. Both messages have the same AND
result, so this example does not demonstrate a forged opposite output.
Correct evaluation and the goal's one-message label restriction are
different requirements.

This is a rejection of this scalar gadget as a standalone message-label
interface. It is not an impossibility theorem for algebraic garbling, does
not invalidate existing point locks, and does not construct another accepted
Bitcoin transaction. A construction with additional secret authentication
inputs must analyze its full interface separately.

## Literature boundary

[Kondi and Patra, CRYPTO 2017](https://eprint.iacr.org/2017/561.pdf) construct
privacy-free formula garbling. Figure 2 uses common zero labels and XOR
shares of the one-output label; the text explicitly allows some opposite
input labels to become known while proving output authenticity. Their
verification algorithm takes encoding information containing both input
labels (Definition 4 and Figure 6). It is not the public point-only checker
implemented here. The local scalar-field AND adaptation does not implement
their XOR gates or claim their full formula theorem.

The inspected PDF has 32 pages, 443,776 bytes and SHA256
`7a94174c813678cb629e65cedfc751e693b6b6b9efac7f6a6f64dd6ea74f75ab`.
This is an interface incompatibility with our stronger input-label
requirement, not a flaw in the cited garbling scheme.

## Reproduction and next requirement

Four focused deterministic tests cover 16 public instances and all 64 input
evaluations. They reproduce 32 complete alternative-input recoveries, of
which 16 have six distinct point commitments. Thirteen changed public
relations/encodings and six malformed message/opening cases are rejected.

Evidence: **locally-reproduced** for the experiment and **inspected** for the
equations and source interface. Deployment: **unclassified**. This host-only
probe produces no script, witness, hint stack, transaction or Core result;
their resource counts are not applicable. It makes no setup benchmark or
onchain-size claim and changes no existing native artifact.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/public_algebraic_gate_probe.py -v
```

A replacement must pass both checks: public algebraic consistency and
restricted access after every permitted opening. Non-reversible translation
or a different complete authentication interface may escape this example;
public affine offsets and point uniqueness alone do not. The existing
encrypted/garbled translator retains its separate public-binding problem.

The [vector-label extension](vector-label-gates.md) now supplies a working
public check and complete-input restriction at a single-gate boundary by
using two scalar coordinates per input label. It includes a discrete-log
embedding and a proof that the one-scalar linear AND interface cannot satisfy
both restrictions. Native delivery cost and full-verifier composition remain
open; this extension does not retroactively fix the scalar gadget above.
