# SHA-1 over u32 bytes

Implements SHA-1 with byte-oriented u32 operations for fixed messages up to 511
bytes. `sha1_prefix` provides a generation-time adapter for retaining only the
first 1..=20 digest bytes.

- **Position:** compatibility construction only; it is not suitable where
  collision resistance is required.
- **Evidence:** differentially validated against standard reference digests and
  internal round checks.
- **Representative result:** a 32-byte hashing fragment is 209,726 bytes.
- **Deployment:** operation-heavy research fragment; complete consensus and
  policy feasibility are configuration-dependent and not established here.
- **Stack contract:** one byte item per input byte; 20 byte items returned.
- **Prefix adapter:** retains the first requested digest bytes without reducing
  the SHA-1 compression cost.

See the [implementation README](../../src/hashes/sha1/README.md) and catalog
record `hash/sha1-u32`.
