# RIPEMD-160 over u32 bytes

Implements the 80-round RIPEMD-160 compression structure using byte-oriented
u32 operations.

- **Position:** compatibility with Bitcoin HASH160-oriented constructions, not
  a default new-protocol hash.
- **Evidence:** differentially validated with standard reference digests and
  internal round tests.
- **Representative results:** a 32-byte hashing fragment is 244,063 bytes; a
  16-byte suffix continuation from a one-block midstate is 243,956 bytes.
- **Security:** the 160-bit output gives at most 80-bit generic collision
  resistance.
- **Stack contract:** consumes byte items and returns 20 digest byte items. The
  midstate continuation consumes exactly 16 suffix bytes and returns the
  digest for a 64-byte prefix plus that suffix.

See the [implementation README](../../src/hashes/ripemd160/README.md) and
catalog record `hash/ripemd160-u32`.
