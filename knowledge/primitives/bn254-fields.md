# BN254 fields

Implements BN254 `Fq`, `Fr`, and the `Fq2/Fq6/Fq12` extension tower over nine
29-bit limbs, with witness-hinted multiplication, inversion, square, and
Frobenius operations.

- **Position:** local arithmetic basis for Groth16-oriented pairing
  verification.
- **Evidence:** differentially validated against arkworks for representative
  operations; two expensive paths are excluded from the default test tier.
- **Measured boundary:** locking sizes cover only the generated operation
  fragment. Stack peaks include all operand and hint items and count the main
  and alt stacks together under the no-stack-limit tapscript executor.
- **Trust boundary:** canonical field range and every hint relation must be
  constrained by the generated verifier.
- **Deployment:** large operations are research-oriented and often use relaxed
  execution.

| Field | Addition bytes / stack peak | Hinted multiplication bytes / stack peak | Hinted square bytes / stack peak |
| --- | ---: | ---: | ---: |
| `Fq` | 415 / 22 | 67,744 / 297 | 67,735 / 297 |
| `Fr` | 415 / 22 | — | — |
| `Fq2` | 846 / 40 | 190,619 / 270 | 136,834 / 342 |
| `Fq6` | 2,538 / 112 | 1,066,421 / 486 | 766,199 / 468 |
| `Fq12` | 5,166 / 220 | 3,217,947 / 882 | 2,155,690 / 684 |

The measured `Fq::hinted_inv` fragment is 67,832 bytes with a 306-item peak.
Sparse multiplication, Frobenius maps, retained-operand variants, validity
predicates, and witness-byte costs remain in the open inventory.

See the [implementation README](../../src/curves/bn254/fields/README.md) and
catalog record `curve/bn254-fields`.
