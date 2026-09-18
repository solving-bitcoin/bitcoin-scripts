# RIPEMD-160 over u32 bytes

Implements the 80-round RIPEMD-160 compression structure using byte-oriented
u32 operations.

- **Position:** compatibility with Bitcoin HASH160-oriented constructions, not
  a default new-protocol hash.
- **Evidence:** differentially validated with standard reference digests and
  internal round tests.
- **Representative result:** a 32-byte hashing fragment is 240,223 bytes.
- **Representative continuation:** a 64-byte prefix plus a 16-byte suffix uses
  a 240,152-byte midstate continuation fragment with a 406-item strict
  combined stack peak.
- **Security:** the 160-bit output gives at most 80-bit generic collision
  resistance.
- **Stack contract:** consumes byte items and returns 20 digest byte items. The
  midstate continuation consumes exactly 16 suffix bytes and returns the
  digest for a 64-byte prefix plus that suffix.

See the [implementation README](../../src/hashes/ripemd160/README.md) and
catalog record `hash/ripemd160-u32`.
