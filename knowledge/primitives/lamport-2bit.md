# Lamport 2-bit commitment

Commits to one of four HASH160 preimages and either returns the selected
two-bit value or proves membership.

- **Position:** minimal local one-time value authentication building block.
- **Evidence:** locally reproduced for all values and wrong-preimage failures.
- **Representative result:** 96 script bytes and an 11-byte witness in the
  documented configuration.
- **Security:** strictly one-time; HASH160 bounds and key-reuse risks apply.
- **Known issue:** the current commit helper clamps out-of-range values to three;
  protocols should prefer explicit rejection semantics.

See the [implementation README](../../src/signatures/lamport/README.md) and
catalog record `signature/lamport-2bit`.
