# Concrete fields

This domain contains mathematical fields and the concrete Bitcoin Script
representations used to implement them. Generic algorithms and representation
machinery live in [`../arithmetic`](../arithmetic/); curve groups and pairings
live in [`../curves`](../curves/).

Paths name the field before the backend:

| Field family | Backend | Canonical module |
| --- | --- | --- |
| Ed25519 base field | biased centered radix-`2^5` signed-table multiply, ordinary domain | `fields::ed25519::u5_balanced_table` |
| Ed25519 base field | balanced radix-`2^9` bigint, factor-8 profile | `fields::ed25519::bigint9` |
| secp256k1 base field | balanced radix-`2^9` bigint, ordinary profile | `fields::secp256k1::bigint9` |
| secp256k1 base field | balanced radix-`2^9` bigint, factor-16 profile | `fields::secp256k1::bigint9::factor16` |
| secp256k1 base field | 46-prime certified RNS | `fields::secp256k1::rns` |
| BN254 tower | nine 29-bit limbs | `fields::bn254::bigint29` |
| F257 | generic `u31` | `fields::f257::u31` |
| F257 | centered log/exp and exact-square lookup | `fields::f257::lookup` |
| F12289 | generic `u31` | `fields::f12289::u31` |
| F12289 | radix-table constant multiplication | `fields::f12289::radix` |
| M31 / QM31 | generic `u31` backend | `fields::m31::{u31,qm31}` |
| BabyBear / BabyBear4 | generic `u31` backend | `fields::babybear::{u31,babybear4}` |

There are no compatibility aliases for the previous locations under
`arithmetic::fields` or `curves::bn254::fields`. This keeps representation
choices visible at every call site and prevents field code from depending on
curve modules.

Each field-family README compares its available backends. Backend READMEs own
the detailed parameters, metrics, witness contract, and validity obligations.
