# Base-16 Winternitz signatures

Implements HASH160 Winternitz chains with standard and compact signatures,
typed message sizes, and list-pick, brute-force, or binary-search verifiers.

- **Position:** current local general-purpose one-time message authentication
  construction and a state-commitment transport mechanism.
- **Evidence:** differentially validated with committed test vectors across all
  typed message lengths.
- **Representative result:** Wots32 list-pick uses 4,908 script bytes and a
  1,477-byte serialized witness.
- **Tradeoff:** compact witnesses increase verification work; verifier choice
  changes script, witness, and stack costs.
- **Security:** keys are strictly one-time and chain security is bounded by
  HASH160 and multi-target effects.

See the [implementation README](../../src/signatures/winternitz/README.md),
[signature comparison](../comparisons/signatures.md), and catalog record
`signature/winternitz-base16`.
