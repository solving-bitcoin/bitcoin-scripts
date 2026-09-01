# Groth16 verification in Bitcoin Script

## Dependency map

```text
Groth16 pairing equation
├── BN254 four-pair verification
│   ├── Miller-loop line evaluation
│   ├── Fq12 sparse multiplication and verification hints
│   └── prepared constant G2 coefficients
├── G1/G2 parsing, validity, and protocol-required subgroup checks
├── scalar/public-input multi-scalar multiplication
├── Fq/Fr/Fq2/Fq6/Fq12 arithmetic over U254 limbs
└── authenticated intermediate-state transport between chunks
    ├── one-time signatures or commitments
    └── transaction/challenge graph
```

## Current local evidence

Field and group operations have deterministic arkworks comparisons. The full
four-pair execution is instance-specific, ignored in the default test suite,
and run with relaxed limits. Small predicate metrics therefore do not establish
the cost or feasibility of a complete verifier.

The upstream BitVM repository describes a Groth16 verifier split into
challengeable chunks and currently reports a very large monolithic script. That
source is `bitvm-repository` in the reference registry; its claims are
`reported` here until reproduced with an immutable upstream revision.

## Required protocol evidence

- exact verification equation and preparation constants;
- complete hint binding and malformed-hint tests;
- point encoding, on-curve, identity, and subgroup policy;
- chunk boundary state and authentication cost;
- maximum strict stack and validation budget per leaf;
- complete transaction weight and policy validation;
- differential execution against an authoritative environment.

See open problems `OP-006`, `OP-007`, and `OP-008`.
