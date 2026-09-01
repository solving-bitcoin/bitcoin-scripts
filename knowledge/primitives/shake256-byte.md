# SHAKE256 over byte lanes

Implements FIPS 202 SHAKE256 with 25 little-endian 64-bit lanes represented by
byte items and a fixed 1,024-byte output.

- **Position:** active local experiment with checked script, witness, and stack
  metric snapshots for a 32-byte input.
- **Evidence:** `differentially-validated`; deterministic local tests compare
  every byte of the 1,024-byte result for empty, short, and exact-rate inputs
  against an independent u64 sponge implementation.
- **Deployment:** consensus-incompatible in raw-output form because 1,024 output
  items alone exceed the 1,000-item combined stack limit. Local correctness
  runs are `research-unlimited` because stack-limit enforcement is disabled.
- **Research direction:** consume output incrementally or expose a smaller
  generation-time output length.
- **Stack contract:** consumes fixed-length byte items and leaves the first of
  1,024 output bytes on top.
- **Representative cost:** a 32-byte input generates a 15,927,814-byte fragment,
  a 65-byte serialized witness, and a 1,709-item combined-stack peak. The
  boundary includes lookup-table setup and cleanup but excludes message pushes,
  output comparison, and a terminal predicate.

See the [implementation README](../../src/hashes/shake256/README.md) and catalog
record `hash/shake256-byte`.
