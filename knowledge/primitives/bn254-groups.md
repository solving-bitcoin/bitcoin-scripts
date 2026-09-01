# BN254 groups and MSM

Implements affine G1/G2 predicates and hinted point operations, plus
constant-base G1 multi-scalar multiplication.

- **Position:** group layer between BN254 fields and the pairing/Groth16
  protocol map.
- **Evidence:** differentially validated against arkworks for representative
  deterministic points.
- **Representative results:** G1 zero test 77 bytes; G2 zero-keep test 260.
- **Trust boundary:** canonical coordinates, on-curve checks, identity handling,
  and required subgroup constraints are protocol obligations.
- **Deployment:** full MSM and hinted point operations are oversized research
  compositions in current local tests.

See the [implementation README](../../src/curves/bn254/groups/README.md) and
catalog record `curve/bn254-groups`.
