# Base-16 Winternitz signatures

Implements HASH160 Winternitz chains with standard and compact signatures,
typed message sizes, and list-pick, brute-force, or binary-search verifiers.

- **Position:** current local general-purpose one-time message authentication
  construction and a state-commitment transport mechanism.
- **Evidence:** locally reproduced with committed self-generated regression
  vectors across all typed message lengths. Those vectors do not constitute an
  independent differential implementation.
- **Representative result:** Wots32 list-pick uses 4,908 script bytes and a
  1,477-byte serialized witness. The Fast bitwise profile reduces the like-for-
  like recovery fragment to 4,327 bytes, or 4,208 bytes when the message is
  cleared, with a documented witness-size/stack tradeoff and relaxed raw
  chain-item length relation.
- **Tradeoff:** compact witnesses increase verification work; verifier choice
  changes script, witness, and stack costs.
- **Security:** keys are strictly one-time and chain security is bounded by
  HASH160 and multi-target effects.
- **Audit notes:** the default list-pick verifier clamps values above the base
  maximum before recovering them, so it authenticates the clamped digit but
  does not enforce raw numeric canonicality. Legacy key generation also clones
  the secret per chain and allocates/sorts all intermediate hashes solely to
  warn about cycles. The random-key wrapper hex-encodes a 20-byte RNG output
  into a 40-byte secret. These are compatibility behaviors, not properties of
  the new Fast API.

See the [implementation README](../../src/signatures/winternitz/README.md),
[Fast implementation](winternitz-fast-base16.md),
[signature comparison](../comparisons/signatures.md), and catalog record
`signature/winternitz-base16`.
