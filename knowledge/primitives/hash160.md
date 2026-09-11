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
byte-order adapter. Callers still need to bind the digest and enforce their
terminal clean-stack predicate.
