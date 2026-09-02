# BN254

BN254 group, multi-scalar multiplication, and pairing-verification building
blocks. They use the
[`fields::bn254::bigint29`](../../fields/bn254/bigint29/) backend.

## Parameters

- Curve: fixed to arkworks `ark_bn254::Config`.
- Base and scalar arithmetic uses 254-bit values in 29-bit limbs by default.
- MSM window: 8 bits; batch size: 8 rows per chunk.
- Pairing entry point is currently specialized to a four-pair Groth16-style
  Miller loop with three fixed G2 inputs and one witness-supplied G2 input.

Detailed parameters and metrics are split across the
[`bigint29` field backend](../../fields/bn254/bigint29/),
[`groups`](groups/README.md), and [`pairing`](pairing/README.md).

## Security

BN254 pairing security is commonly treated as roughly 100 bits against modern
finite-field discrete-log attacks, not 128 bits. Field arithmetic alone has no
security property. Protocol soundness depends on subgroup checks, point
validation, correct hint binding, and the enclosing proof system.

## Script compatibility and standardness

Simple fragments use ordinary Script opcodes, but realistic MSM and pairing
compositions are very large and some tests intentionally execute without the
default stack limit. Treat the module as tapscript research code; it is not a
blanket claim of standard bare/P2SH/P2WSH deployability.

## Witness and hints

Basic push/add/subtract helpers do not need hints. Multiplication, inversion,
MSM, and pairing helpers return mandatory witness hints that the generated
script verifies. Hints are not trusted inputs, but omitting or misordering them
causes verification failure.

## Test tiers

Normal `cargo test` skips the two end-to-end BN254 Script executions that take
more than a minute:

- `test_bn254_fq6_hinted_mul_keep_elements`
- `test_hinted_quad_miller_loop_with_c_wi`

They remain compiled and can be run explicitly with:

```sh
cargo test --lib -- --ignored
```

To run just one, pass its full or unique test-name substring before
`-- --ignored`.
