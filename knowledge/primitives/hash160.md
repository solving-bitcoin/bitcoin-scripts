# HASH160 composition

This primitive composes the local byte-oriented SHA-256 and RIPEMD-160
implementations as `RIPEMD160(SHA256(message))`, matching Bitcoin's HASH160
construction.

- **Evidence:** `differentially-validated`; empty, `abc`, and both 55/56-byte
  padding boundaries are checked against the `bitcoin` hash implementations.
- **Deployment:** `unclassified`; the representative composition passes the
  local 1,000-item stack check, but it has not been compared with Bitcoin Core
  consensus or relay-policy execution.
- **Stack contract:** consumes one byte-valued item per input byte and leaves
  20 digest bytes with the first byte on top.
- **Representative cost:** the 32-byte configuration is recorded in the
  implementation README and catalog. It includes both component fragments but
  excludes message pushes and output comparison.

The intermediate SHA-256 digest remains in the same byte-item representation
expected by RIPEMD-160, so the composition does not add a serialization or
byte-order adapter. The shared-table variant keeps the common 256-item lookup
resident across both stages, removing one table setup/cleanup pair. Callers
still need to bind the digest and enforce their terminal clean-stack predicate.

## Shared lookup boundary

The research question is whether the SHA-256 and RIPEMD-160 stages can share
their identical byte-logic table without changing the digest or exceeding the
combined stack limit. The shared variant is `locally-reproduced`: the empty,
`abc`, and 55/56-byte padding-boundary vectors match the independent hash
implementation, and negative one and 256-byte hostile inputs are rejected.

For a 32-byte message, the shared table costs 756,167 locking-script bytes,
324 bytes less than the ordinary composition, with the same 65-byte witness and
856-item strict local peak. The boundary includes table setup and cleanup,
excludes input pushes and digest comparison, uses zero hint items, and remains
`research-unlimited`/`unclassified` with respect to deployment because Core
consensus and policy validation were not performed.
