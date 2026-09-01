# BN254 fields

Implements BN254 `Fq`, `Fr`, and the `Fq2/Fq6/Fq12` extension tower over nine
29-bit limbs, with witness-hinted multiplication, inversion, square, and
Frobenius operations.

- **Position:** local arithmetic basis for Groth16-oriented pairing
  verification.
- **Evidence:** differentially validated against arkworks for representative
  operations; two expensive paths are excluded from the default test tier.
- **Representative results:** Fq and Fr addition are 415 bytes; Fq2 addition is
  846 bytes. Full hinted-operation cost is operation-specific.
- **Trust boundary:** canonical field range and every hint relation must be
  constrained by the generated verifier.
- **Deployment:** large operations are research-oriented and often use relaxed
  execution.

See the [implementation README](../../src/curves/bn254/fields/README.md) and
catalog record `curve/bn254-fields`.
