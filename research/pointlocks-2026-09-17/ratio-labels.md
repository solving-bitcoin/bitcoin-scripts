# Relative-log labels from linear scalar openings

Objective: determine whether replacing scalar labels by ratios can lower
the number of native openings needed for publicly checked label translation.

**Ratios of fixed public affine point forms do not give that compression.**
A hidden ratio needs both numerator and denominator scalar forms in the
disclosed span. A ratio that is determined without them is a publicly
checkable constant. This is a scoped result, not a rejection of nonlinear
point-lock constructions.

- [Exact proof, DLP reduction and limits](../../knowledge/negative-results/ratio-label-reconstruction.md)
- [Executable reference](ratio_label_probe.py)
- [Deterministic results and source hashes](ratio-label.json)
- [Previous correlated subset boundary](../../knowledge/negative-results/linear-subset-classification.md)

The candidate label is `ell=log_B(A)`, with A=a(x)G and B=b(x)G. Both a and b
are public affine forms in hidden setup scalars x. The opened scalars have
the form Mx. The probe classifies each resulting affine fiber as an invalid
base, a recoverable pair of forms, a public constant, or an undetermined
ratio. It includes the exception x-y=0: x/y=1 is determined, but X=Y makes
that value publicly recognizable already.

The finite-field enumeration is independent of the classifier: it evaluates
every compatible scalar assignment and compares all defined ratios.

| Field | Affine forms | Disclosure matrices | Compared cases |
| --- | ---: | ---: | ---: |
| F3, two hidden coordinates | 27 | 5 | 13,851 |
| F5, two hidden coordinates | 125 | 5 | 640,625 |

All four classifications occur. Matrices include no openings, one coordinate,
a sum, full disclosure and a redundant equation. Zero bases, proportional
forms, affine offsets and zero outputs are included; zero outputs are not
claimed to be hidden labels.

Twelve deterministic secp256k1 fixtures separately test the exact computational
reduction. The embedding uses only the challenge point X=zG to create the
setup, then a test oracle provides a correct ratio label. The extractor
recovers z in all twelve cases and rejects twelve changed labels. Three
profiles cover two varying endpoint forms, a fixed denominator and correlated
scalar openings. These are deliberate test disclosures, not attacks on
external keys. Other controls check inversion/chaining, zero bases, malformed
points, noncanonical scalars, inconsistent openings and degenerate embeddings.

Nine tests passed in 1.487 seconds on the local run. That is diagnostic test
runtime, **not** setup time for the publication scheme. The deterministic
report does not use the runtime as a setup metric.

Evidence: **locally-reproduced** tests, **inspected** proof. Deployment:
**unclassified**. This is host-only algebra; Bitcoin script bytes, witness
bytes, hints, entry items, stack peak, opcodes, validation budget, Core
execution, full onchain cost and complete setup benchmarks are N/A. Existing
native scripts, transaction artifacts, setup timings and decoder APIs remain
unchanged.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/ratio_label_probe.py -v
```

A next candidate must specify what additional publicly checked nonlinear
relation or different native opening makes its labels available. Merely
writing the existing linear forms as relative discrete logarithms leaves the
missing translation unresolved.

The subsequent [DH quartet experiment](dh-quartet-labels.md) changes the
output type to secret group elements. It does deliver two such labels per
scalar opening, while leaving native delivery and public garbling binding
open; it is outside the scalar-ratio result above.
