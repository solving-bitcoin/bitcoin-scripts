# RIPEMD-160 over u32 bytes

Implements the 80-round RIPEMD-160 compression structure using byte-oriented
u32 operations.

- **Position:** compatibility with Bitcoin HASH160-oriented constructions, not
  a default new-protocol hash.
- **Evidence:** differentially validated with standard reference digests and
  internal round tests.
- **Representative result:** a 32-byte hashing fragment is 240,223 bytes.
- **Security:** the 160-bit output gives at most 80-bit generic collision
  resistance.
- **Stack contract:** consumes byte items and returns 20 digest byte items.
- **Prefix adapter:** `ripemd160_prefix` can retain `1..=20` leading digest
  bytes for protocols that intentionally select a shorter binding.

## Prefix research question

Can a fixed RIPEMD-160 output prefix reduce a Script fragment's composition
cost? The hypothesis was that it would reduce terminal output items and
comparison work, but not the 80-round compression cost or the peak reached
while the compressor is active. The comparison is against the existing full
20-byte output with the same 32-byte message and witness boundary.

The prefix adapter uses no hints and has no additional cryptographic claim.
Its witness and message assumptions are unchanged: every supplied item must
be a canonical byte, and the caller must bind the selected prefix length.
For the representative 8-byte prefix, the unoptimized fragment is 240,251
bytes versus 240,223 bytes for the full output, with a 65-byte serialized
32-item witness, a 406-item combined peak, and 169,971 static non-push
opcodes. Both executions use the repository's `research-unlimited` metric
boundary with stack enforcement disabled; neither is consensus or policy
validation.

Deterministic tests compare the prefix against the independent rust-bitcoin
RIPEMD-160 reference for prefix lengths 1, 8, 19, and 20, and for message
lengths 0, 55, 56, 63, and 64. They reject prefix lengths 0 and 21 and missing
message input. Byte range and canonicality remain caller obligations.

The result is a terminal-output adapter, not a new compression algorithm. It
is useful only when a protocol intentionally accepts the lower collision
bound. An 8-byte prefix has at most a 32-bit generic collision bound and an
ideal 64-bit preimage bound; callers needing all 160 digest bits are strictly better served by the
existing full output.

See the [implementation README](../../src/hashes/ripemd160/README.md) and
catalog record `hash/ripemd160-u32`.
