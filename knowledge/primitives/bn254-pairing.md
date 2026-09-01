# BN254 pairing verifier

Implements prepared affine G2 operations and a hinted four-pair Miller-loop and
final-verification path specialized for Groth16-style equations.

- **Position:** protocol-specific pairing path rather than a generic pairing
  API with a single stable cost.
- **Evidence:** locally reproduced against arkworks components; the full
  end-to-end Miller-loop execution is an explicitly ignored expensive test.
- **Metrics:** instance-specific and not yet represented by a stable catalog
  byte count.
- **Trust boundary:** prepared coefficients, subgroup and non-degeneracy checks,
  evaluation points, and all hint bindings are essential.
- **Deployment:** research-unlimited; intended to be split into challengeable
  protocol chunks rather than used as a monolithic standard script.

See the [implementation README](../../src/curves/bn254/pairing/README.md),
[Groth16 protocol map](../protocols/groth16-bitcoin-script.md), and catalog record
`curve/bn254-pairing`.
