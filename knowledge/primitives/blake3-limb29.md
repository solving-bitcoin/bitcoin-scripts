# BLAKE3 over tracked limbs

Implements BLAKE3 for messages up to one 1,024-byte chunk using tracked-stack
u4 and bigint machinery.

- **Position:** locally used to compress intermediate protocol state; supports a
  bounded single-chunk range rather than the full unbounded tree API.
- **Evidence:** differentially validated against official vectors.
- **Representative result:** a 64-byte, 29-bit-limb compute fragment is 77,777
  bytes.
- **Tradeoff:** maximum depth is parameter-dependent and some tests deliberately
  disable the stack limit.
- **Security:** inherited from BLAKE3 for the supported construction range.

See the [implementation README](../../src/hashes/blake3/README.md) and catalog
record `hash/blake3-limb29`.
