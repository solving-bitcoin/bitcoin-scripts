# Taxonomy

Stable terminology makes the atlas searchable and prevents equivalent
constructions from being hidden behind local module names.

## Primitive classes

- `arithmetic/scriptnum`: arithmetic on minimally encoded Bitcoin Script
  integers.
- `arithmetic/word`: fixed-width bit or digit representations such as u4/u32.
- `arithmetic/field`: prime and extension-field operations.
- `arithmetic/bigint`: multi-limb integers.
- `arithmetic/rns`: residue-number representations.
- `commitment/integer`: openings that authenticate and return small integers.
- `hash/fixed`: fixed-output hashes.
- `hash/xof`: extendable-output functions.
- `signature/schnorr`: secp256k1 Schnorr verification constructions.
- `signature/one-time`: hash-based one-time authentication constructions.
- `introspection/transaction`: constructions that expose or bind transaction
  information through existing signature and Script semantics.
- `cipher/block`: block-cipher evaluation.
- `curve/field`, `curve/group`, `curve/pairing`: elliptic-curve and pairing
  components.

## Orthogonal technique tags

- `lookup-table`, `half-table`, `log-exp-table`, `radix-table`, `streaming-table`
- `batch-lookup`, `branch-map`
- `addition-chain`, `limb-arithmetic`, `digit-arithmetic`, `rns`
- `witness-hints`, `constant-embedding`, `tracked-stack`, `batch-inversion`
- `affine-coordinates`, `glv-endomorphism`, `jacobian-coordinates`,
  `signed-window`, `taptree-lookup`, `wnaf`
- `hash-chain`, `mixed-hash-path`, `sponge`, `pairing`

## Status is not evidence

`experimental` describes maturity. `locally-reproduced` describes evidence.
A construction can be both experimental and reproducibly measured. Likewise,
an active external construction may be only `reported` here.

## Construction versus configuration

A construction is an algorithm and representation with stable semantics. A
configuration fixes parameters and cost boundaries. For example, u4 SHA-256 is
a construction; a 32-byte input with table setup included is a configuration.
Comparisons operate on configurations, not names alone.
