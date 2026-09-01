# Hash-authenticated state transitions

## Dependency map

```text
Protocol state
├── chosen stack representation
├── serialization and canonicality rules
├── hash implementation
│   ├── representation conversion
│   ├── padding/domain separation
│   └── digest comparison
└── transition predicate and clean-stack termination
```

## Selection considerations

BLAKE3, SHA-256, RIPEMD-160, SHA-1, and SHAKE256 have different semantics,
security contexts, representations, message ranges, and output shapes. Script
bytes alone are insufficient. A protocol map must include conversion from the
live state, digest commitment placement, repeated-hash amortization, and strict
stack coexistence.

SHA-1 is compatibility-only. RIPEMD-160 is useful for Bitcoin-compatible
160-bit commitments but has an 80-bit ideal collision bound. Raw SHAKE256's
current 1,024-item output is consensus-incompatible. Local BLAKE3 supports only
the documented single-chunk range.
