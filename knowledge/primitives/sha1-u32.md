# SHA-1 over u32 bytes

Implements SHA-1 with byte-oriented u32 operations for fixed messages up to 511
bytes. `sha1_prefix` provides a generation-time adapter for retaining only the
first 1..=20 digest bytes.

- **Position:** compatibility construction only; it is not suitable where
  collision resistance is required.
- **Evidence:** differentially validated against standard reference digests and
  internal round checks.
- **Representative results:** a 32-byte hashing fragment is 205,558 bytes; the
  8-byte prefix profile is 205,586 bytes with a 65-byte witness, 632-item
  research-unlimited peak, and 144,693 static non-push opcodes; the
  64-byte-prefix/16-byte-suffix midstate continuation is 205,489 script bytes
  with a 33-byte fixture witness, a 49-byte canonical maximum, and a 632-item
  strict composition peak.
- **Deployment:** operation-heavy research fragment; complete consensus and
  policy feasibility are configuration-dependent and not established here.
- **Stack contract:** one byte item per input byte; 20 byte items returned. The
  midstate continuation consumes exactly 16 canonical byte-valued suffix
  items and uses a 64-bit big-endian length field containing 640.
- **Prefix adapter:** retains the first requested digest bytes without reducing
  the SHA-1 compression cost.
- **Prefix security:** an 8-byte prefix has at most a 32-bit generic collision
  bound and an ideal 64-bit preimage bound; SHA-1 remains collision-broken.

See the [implementation README](../../src/hashes/sha1/README.md) and catalog
record `hash/sha1-u32`.
