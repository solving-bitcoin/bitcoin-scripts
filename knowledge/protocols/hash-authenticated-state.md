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
the documented single-chunk range. For messages of at most 32 bytes, its sparse
direct-u4 profile minimizes the checked fragment and requires two nibble items
per byte. For longer inputs, limb width is a protocol-level choice: smaller
limbs reduce script bytes, while wider limbs retain more stack headroom across
multiple blocks. Host-known constants are packed at generation time, but
witness-backed state still needs the documented numeric range checks, any
protocol-required byte-encoding canonicality, and a digest-binding predicate.
Values in a wholly ignored selected-limb final half-block are padding, not
authenticated protocol state.

For [binary hash paths](../primitives/hash-path-integer.md), bind the starting
state independently: otherwise changing `(x, 1)` to `(SHA256(x), 0)` preserves
the result. Nested paths equal the joined path and do not encode round
boundaries. Binohash/Lamport consumers must bind the normalized branch bits,
not the original selector bytes. A complete wrapper and its costs remain OP-020.


A [prefix/delta sequence adapter](../primitives/u4-prefix-sum.md) preserves
numeric sequence content when the initial value is retained. A protocol must
also bind that initial value, all deltas and the canonical byte encoding into
its authenticated state. The local round trip prices checking and routing,
but includes no hash or commitment; it establishes arithmetic reconstruction
only.
